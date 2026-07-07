"""메일 게이트웨이(janus.com) 연동 — 사용자별 IMAP 수신 + SMTP 발송.

각 소통플랫폼 사용자는 <username>@janus.com 사서함을 가지며(가입 비번=메일 비번),
백엔드가 그 자격으로 IMAP/SMTP를 대행해 메일함에서 본인 메일을 주고받는다.
- 수신: IMAPS(993)로 INBOX 조회(읽기 전용 — 서버 원본 변경 안 함)
- 발송: SMTP(25) 릴레이/STARTTLS, From=사용자 주소. 가능하면 IMAP Sent에도 적재.
- 자체서명 인증서 환경을 위해 TLS 검증은 config로 켜고 끔(MAIL_TLS_VERIFY).
"""
import imaplib
import re
import smtplib
import ssl
import time
from email import encoders, message_from_bytes
from email.header import decode_header, make_header
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid, parsedate_to_datetime

import config


def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not config.MAIL_TLS_VERIFY:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _dec(s: str | None) -> str:
    if not s:
        return ""
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def _extract_body(msg) -> str:
    """text/plain 우선, 없으면 text/html에서 본문 추출."""
    if msg.is_multipart():
        for want in ("text/plain", "text/html"):
            for part in msg.walk():
                if part.get_content_type() != want:
                    continue
                if "attachment" in str(part.get("Content-Disposition", "")).lower():
                    continue
                try:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace")
                except Exception:
                    continue
        return ""
    try:
        return msg.get_payload(decode=True).decode(
            msg.get_content_charset() or "utf-8", errors="replace")
    except Exception:
        return msg.get_payload() or ""


def _is_attachment(part) -> bool:
    """첨부 파트 판별: Content-Disposition=attachment 이거나, 본문(text)이 아닌데 파일명이 있는 경우."""
    if part.get_content_maintype() == "multipart":
        return False
    cd = str(part.get("Content-Disposition", "")).lower()
    if "attachment" in cd:
        return True
    fn = part.get_filename()
    return bool(fn and part.get_content_type() not in ("text/plain", "text/html"))


def _list_attachments(msg) -> list[dict]:
    """첨부 메타데이터 목록 [{idx, name, ctype, size}]. idx는 첨부 파트의 순번(다운로드 식별용)."""
    out: list[dict] = []
    if not msg.is_multipart():
        return out
    i = 0
    for part in msg.walk():
        if not _is_attachment(part):
            continue
        name = _dec(part.get_filename()) or f"attachment-{i + 1}"
        try:
            size = len(part.get_payload(decode=True) or b"")
        except Exception:
            size = 0
        out.append({"idx": i, "name": name, "ctype": part.get_content_type(), "size": size})
        i += 1
    return out


def _parse(msg, uid: str) -> dict:
    dt = None
    try:
        dt = parsedate_to_datetime(msg.get("Date"))
    except Exception:
        pass
    body = _extract_body(msg)
    return {
        "uid": uid,
        "message_id": msg.get("Message-ID", ""),
        "from": _dec(msg.get("From")),
        "to": _dec(msg.get("To")),
        "subject": _dec(msg.get("Subject")) or "(제목 없음)",
        "date": dt.isoformat() if dt else (msg.get("Date") or ""),
        "preview": " ".join(body.split())[:200],
        "body": body,
        "attachments": _list_attachments(msg),
    }


def fetch_attachment(address: str, password: str, uid: str, source: str = "inbox",
                     idx: int = 0) -> tuple[str, str, bytes] | None:
    """특정 메일(uid)의 idx번째 첨부 1건을 (파일명, content-type, bytes)로 반환. 없으면 None."""
    folders = {"sent": list(_SENT_FOLDERS), "trash": list(_TRASH_FOLDERS)}.get(source, ["INBOX"])
    M = imaplib.IMAP4_SSL(config.MAIL_GATEWAY_HOST, config.MAIL_IMAP_PORT, ssl_context=_ssl_ctx())
    try:
        M.login(address, password)
        for folder in folders:
            typ, _ = M.select(folder, readonly=True)
            if typ != "OK":
                continue
            typ, md = M.uid("FETCH", str(uid), "(RFC822)")
            if typ != "OK" or not md or not md[0]:
                continue
            msg = message_from_bytes(md[0][1])
            cur = 0
            for part in msg.walk():
                if not _is_attachment(part):
                    continue
                if cur == int(idx):
                    name = _dec(part.get_filename()) or f"attachment-{cur + 1}"
                    return name, part.get_content_type(), (part.get_payload(decode=True) or b"")
                cur += 1
            return None
        return None
    except Exception:  # noqa: BLE001
        return None
    finally:
        try:
            M.logout()
        except Exception:
            pass


def fetch_mailbox(address: str, password: str, folder: str = "INBOX", limit: int = 30) -> list[dict]:
    """사용자 사서함에서 최근 메일 목록(헤더+본문) 반환. 읽기 전용."""
    M = imaplib.IMAP4_SSL(config.MAIL_GATEWAY_HOST, config.MAIL_IMAP_PORT, ssl_context=_ssl_ctx())
    out: list[dict] = []
    try:
        M.login(address, password)
        typ, _ = M.select(folder, readonly=True)
        if typ != "OK":           # 사서함 미초기화/없음 → 빈 목록
            return []
        typ, data = M.uid("SEARCH", None, "ALL")   # UID 기반(안정적 식별)
        if typ != "OK":
            return []
        ids = data[0].split() if data and data[0] else []
        for u in reversed(ids[-limit:]):
            typ, md = M.uid("FETCH", u, "(RFC822)")
            if not md or not md[0]:
                continue
            out.append(_parse(message_from_bytes(md[0][1]), u.decode()))
    finally:
        try:
            M.logout()
        except Exception:
            pass
    return out


_SENT_FOLDERS = ("Sent", "Sent Messages", "INBOX.Sent")
_TRASH_FOLDERS = ("Trash", "INBOX.Trash")

# LIST 응답 1줄 파싱: (flags) "delim" name   예) (\HasNoChildren \Sent) "." Sent
_LIST_RE = re.compile(r'^\((?P<flags>[^)]*)\)\s+(?:"(?P<delim>[^"]*)"|NIL)\s+(?P<name>.+?)\s*$')


def _list_folders(M) -> list[tuple[str, str]]:
    """서버 사서함 목록을 [(이름, 소문자 flags)]로 반환."""
    out: list[tuple[str, str]] = []
    try:
        typ, data = M.list()
        if typ != "OK":
            return out
        for raw in data or []:
            line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else (raw or "")
            m = _LIST_RE.match(line.strip())
            if not m:
                continue
            name = m.group("name").strip()
            if len(name) >= 2 and name[0] == '"' and name[-1] == '"':
                name = name[1:-1]
            out.append((name, m.group("flags").lower()))
    except Exception:  # noqa: BLE001
        pass
    return out


def _resolve_sent_folder(M, create: bool = False) -> str | None:
    """이 계정의 'Sent' 사서함명을 결정. 특수용도(\\Sent) > 관용명 순.

    create=True면 어디에도 없을 때 'Sent'를 생성·구독하고 그 이름을 반환한다.
    (Dovecot 등은 미존재 사서함 APPEND를 거부 → 보낸 메일이 안 쌓이는 문제 방지)
    """
    folders = _list_folders(M)
    for name, flags in folders:               # 1) 특수용도 \Sent
        if "\\sent" in flags:
            return name
    names = {n.lower(): n for n, _ in folders}  # 2) 관용명(대소문자 무시)
    for cand in _SENT_FOLDERS:
        if cand.lower() in names:
            return names[cand.lower()]
    if create:                                 # 3) 없음 → 생성
        try:
            M.create("Sent")
        except Exception:  # noqa: BLE001
            pass
        try:
            M.subscribe("Sent")
        except Exception:  # noqa: BLE001
            pass
        return "Sent"
    return None


def fetch_sent(address: str, password: str, limit: int = 30) -> list[dict]:
    """보낸 편지함 조회: 특수용도(\\Sent) 폴더 우선, 없으면 관용명을 순회. 읽기 전용."""
    M = imaplib.IMAP4_SSL(config.MAIL_GATEWAY_HOST, config.MAIL_IMAP_PORT, ssl_context=_ssl_ctx())
    out: list[dict] = []
    try:
        M.login(address, password)
        resolved = _resolve_sent_folder(M, create=False)
        candidates = ([resolved] if resolved else []) + [b for b in _SENT_FOLDERS if b != resolved]
        for folder in candidates:
            if not folder:
                continue
            typ, _ = M.select(folder, readonly=True)
            if typ != "OK":
                continue
            typ, data = M.uid("SEARCH", None, "ALL")
            if typ != "OK":
                continue
            ids = data[0].split() if data and data[0] else []
            for u in reversed(ids[-limit:]):
                typ, md = M.uid("FETCH", u, "(RFC822)")
                if not md or not md[0]:
                    continue
                out.append(_parse(message_from_bytes(md[0][1]), u.decode()))
            return out          # 첫 유효 폴더에서 종료(빈 폴더여도 그게 Sent임)
        return out
    finally:
        try:
            M.logout()
        except Exception:
            pass


def _ensure_trash(M) -> str:
    """휴지통 폴더명을 찾고, 없으면 생성해 반환."""
    for box in _TRASH_FOLDERS:
        typ, _ = M.select(box)
        if typ == "OK":
            return box
    try:
        M.create(_TRASH_FOLDERS[0])
        try:
            M.subscribe(_TRASH_FOLDERS[0])
        except Exception:
            pass
    except Exception:
        pass
    return _TRASH_FOLDERS[0]


def _find_trash(M) -> str | None:
    for box in _TRASH_FOLDERS:
        typ, _ = M.select(box)
        if typ == "OK":
            return box
    return None


def _copy_delete(M, uid: str, dest: str) -> bool:
    """현재 선택된 폴더에서 uid를 dest로 복사한 뒤 원본을 삭제(\\Deleted+EXPUNGE).

    MOVE(RFC6851) 미지원 서버에서도 동작하도록 COPY 기반으로 구현.
    uid가 현재 폴더에 없으면 COPY가 실패(NO)하므로 False를 반환한다.
    """
    typ, _ = M.uid("COPY", str(uid), dest)
    if typ != "OK":
        return False
    M.uid("STORE", str(uid), "+FLAGS", "(\\Deleted)")
    M.expunge()
    return True


def fetch_trash(address: str, password: str, limit: int = 30) -> list[dict]:
    """휴지통 폴더(이름 변형 자동 탐색)에서 메일 목록을 반환."""
    for box in _TRASH_FOLDERS:
        try:
            msgs = fetch_mailbox(address, password, box, limit)
            if msgs:
                return msgs
        except Exception:
            continue
    return []


def move_to_trash(address: str, password: str, uid: str, source: str = "inbox") -> bool:
    """받은/보낸 편지함의 메일(uid)을 휴지통으로 이동. source: inbox|sent."""
    srcs = list(_SENT_FOLDERS) if source == "sent" else ["INBOX"]
    M = imaplib.IMAP4_SSL(config.MAIL_GATEWAY_HOST, config.MAIL_IMAP_PORT, ssl_context=_ssl_ctx())
    try:
        M.login(address, password)
        trash = _ensure_trash(M)
        for src in srcs:
            typ, _ = M.select(src)             # 쓰기 가능(readonly 아님)
            if typ != "OK":
                continue
            if _copy_delete(M, uid, trash):    # 해당 폴더에 uid가 있으면 성공
                return True
        return False
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            M.logout()
        except Exception:
            pass


def restore_from_trash(address: str, password: str, uid: str) -> bool:
    """휴지통의 메일(uid)을 받은편지함(INBOX)으로 복원."""
    M = imaplib.IMAP4_SSL(config.MAIL_GATEWAY_HOST, config.MAIL_IMAP_PORT, ssl_context=_ssl_ctx())
    try:
        M.login(address, password)
        trash = _find_trash(M)
        if not trash:
            return False
        typ, _ = M.select(trash)
        if typ != "OK":
            return False
        return _copy_delete(M, uid, "INBOX")
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            M.logout()
        except Exception:
            pass


def purge_trash(address: str, password: str, uid: str | None = None) -> bool:
    """휴지통에서 영구 삭제. uid 지정 시 1건, 없으면 휴지통 전체 비우기."""
    M = imaplib.IMAP4_SSL(config.MAIL_GATEWAY_HOST, config.MAIL_IMAP_PORT, ssl_context=_ssl_ctx())
    try:
        M.login(address, password)
        trash = _find_trash(M)
        if not trash:
            return True                        # 휴지통 자체가 없으면 비울 것도 없음
        typ, _ = M.select(trash)
        if typ != "OK":
            return False
        if uid:
            M.uid("STORE", str(uid), "+FLAGS", "(\\Deleted)")
        else:
            typ, data = M.uid("SEARCH", None, "ALL")
            ids = data[0].split() if (typ == "OK" and data and data[0]) else []
            for u in ids:
                M.uid("STORE", u, "+FLAGS", "(\\Deleted)")
        M.expunge()
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        try:
            M.logout()
        except Exception:
            pass


def _append_sent(address: str, password: str, raw: bytes) -> None:
    """발송한 메일을 사서함 'Sent'에 적재. 폴더가 없으면 생성 후 적재한다."""
    if not password:          # 시스템 발신(릴레이)에는 사서함이 없으므로 적재 생략
        return
    try:
        M = imaplib.IMAP4_SSL(config.MAIL_GATEWAY_HOST, config.MAIL_IMAP_PORT, ssl_context=_ssl_ctx())
        try:
            M.login(address, password)
            box = _resolve_sent_folder(M, create=True) or "Sent"
            when = imaplib.Time2Internaldate(time.time())
            try:
                M.append(box, "\\Seen", when, raw)
            except Exception:                       # 경합/이름차이 → Sent 생성 후 1회 재시도
                try:
                    M.create("Sent")
                except Exception:
                    pass
                M.append("Sent", "\\Seen", when, raw)
        finally:
            try:
                M.logout()
            except Exception:
                pass
    except Exception:
        pass


def send_mail(from_addr: str, password: str, to_addr: str, subject: str, body: str,
              html: str | None = None, attachments: list[dict] | None = None,
              in_reply_to: str | None = None) -> tuple[bool, str]:
    """게이트웨이 SMTP로 발송(From=사용자/시스템). 25 릴레이/STARTTLS. 반환=(성공, 메시지).

    html이 주어지면 multipart(text+html)로 발송(메일 클라이언트가 HTML 표시).
    attachments=[{name, data(bytes)}]가 있으면 multipart/mixed로 파일을 첨부한다.
    password가 비면 인증 없이 릴레이(시스템 단계 알림 메일 등)로 발송한다.
    """
    attachments = attachments or []

    def _body_part():
        if html:
            alt = MIMEMultipart("alternative")
            alt.attach(MIMEText(body or " ", "plain", "utf-8"))
            alt.attach(MIMEText(html, "html", "utf-8"))
            return alt
        return MIMEText(body or " ", "plain", "utf-8")

    if attachments:
        msg = MIMEMultipart("mixed")
        msg.attach(_body_part())
        for att in attachments:
            data = att.get("data") or b""
            part = MIMEBase("application", "octet-stream")
            part.set_payload(data)
            encoders.encode_base64(part)
            fname = att.get("name") or "attachment"
            # RFC2231(filename*)로 비ASCII(한글) 파일명 안전 처리
            part.add_header("Content-Disposition", "attachment", filename=("utf-8", "", fname))
            msg.attach(part)
    elif html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body or " ", "plain", "utf-8"))
        msg.attach(MIMEText(html, "html", "utf-8"))
    else:
        msg = MIMEText(body, "plain", "utf-8")
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=config.MAIL_DOMAIN)
    if in_reply_to:                       # 회신: 원본과 스레드로 연결
        msg["In-Reply-To"] = in_reply_to
        msg["References"] = in_reply_to
    raw = msg.as_string().encode("utf-8")
    try:
        s = smtplib.SMTP(config.MAIL_GATEWAY_HOST, config.MAIL_SMTP_PORT, timeout=15)
        s.ehlo()
        if config.MAIL_SMTP_STARTTLS and s.has_extn("starttls"):
            s.starttls(context=_ssl_ctx())
            s.ehlo()
        if password and s.has_extn("auth"):   # 릴레이면 불필요, 가능하면 인증
            try:
                s.login(from_addr, password)
            except Exception:
                pass
        s.sendmail(from_addr, [to_addr], raw)
        s.quit()
    except Exception as exc:  # noqa: BLE001
        return False, f"발송 실패: {exc}"
    _append_sent(from_addr, password, raw)
    return True, f"발송 완료 → {to_addr}"


def mark_seen(address: str, password: str, uid: str) -> bool:
    """메일(UID)을 읽음(\\Seen)으로 표시. 안읽음 배지 감소용."""
    try:
        M = imaplib.IMAP4_SSL(config.MAIL_GATEWAY_HOST, config.MAIL_IMAP_PORT, ssl_context=_ssl_ctx())
        M.login(address, password)
        M.select("INBOX")                       # 쓰기 가능(readonly 아님)
        M.uid("STORE", str(uid), "+FLAGS", "(\\Seen)")
        M.logout()
        return True
    except Exception:  # noqa: BLE001
        return False


def unseen_count(address: str, password: str) -> int:
    """INBOX의 안 읽은(UNSEEN) 메일 수. 실패 시 0."""
    try:
        M = imaplib.IMAP4_SSL(config.MAIL_GATEWAY_HOST, config.MAIL_IMAP_PORT, ssl_context=_ssl_ctx())
        M.login(address, password)
        typ, _ = M.select("INBOX", readonly=True)
        if typ != "OK":
            M.logout()
            return 0
        typ, data = M.search(None, "UNSEEN")
        M.logout()
        if typ != "OK" or not data or not data[0]:
            return 0
        return len(data[0].split())
    except Exception:  # noqa: BLE001
        return 0


def verify_account(address: str, password: str) -> tuple[bool, str]:
    """사서함 로그인 가능 여부 확인(가입/바인딩 검증용)."""
    try:
        M = imaplib.IMAP4_SSL(config.MAIL_GATEWAY_HOST, config.MAIL_IMAP_PORT, ssl_context=_ssl_ctx())
        M.login(address, password)
        M.logout()
        return True, "사서함 인증 성공"
    except Exception as exc:  # noqa: BLE001
        return False, f"사서함 인증 실패: {exc}"
