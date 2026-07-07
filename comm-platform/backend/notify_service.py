"""티켓 단계별 외부 알림 — 카톡(외부 API) + 이메일(기록).

설계 원칙
- 설정이 비어 있으면 '드라이런'(실제 발송 없이 이력만) → 폐쇄망/무자격증명 환경에서도 안전.
- 카톡: (1) 범용 웹훅 URL(KAKAO_NOTIFY_URL) 우선, (2) 없으면 Kakao '나에게 보내기'(KAKAO_ACCESS_TOKEN).
- 이메일: 기존 smtp_service 재사용(드라이런 폴백). 발송 + 인앱 Mail 기록으로 '기록으로 남김'.
- 모든 알림 시도는 EventHistory('알림')에 결과를 남겨 티켓 처리 이력에서 추적 가능.

주의: 외부 호출은 동기로 수행(짧은 타임아웃). 대량 운영 시 큐/비동기 전환 권장.
"""
import html as _html
import json
import threading
import time
from datetime import datetime, timedelta

import requests

import config
import mail_gateway
from models import EventHistory, User


def _now_kst() -> str:
    """현재 시각(KST) — 서버 타임존과 무관하게 UTC+9로 계산."""
    return (datetime.utcnow() + timedelta(hours=9)).strftime("%Y-%m-%d %H:%M")

_SEV = {"3": ("고위험", "#dc2626"), "2": ("주의", "#c2740a"), "1": ("낮음", "#15a34a")}
_SEV_EMOJI = {"3": "🔴 고위험", "2": "🟠 주의", "1": "🟢 낮음"}

# ── 알림 폭주 가드 ──────────────────────────────────────────────
# DDoS·스캔 등으로 이벤트가 쏟아질 때, 팀별 발송을 슬라이딩 윈도우로 상한하고
# 초과분은 개별 발송 대신 '요약 1건'으로 대체한다. (텔레그램 429·서버 행 방지)
_FLOOD_MAX = int(getattr(config, "NOTIFY_RATE_MAX", 0) or 10)   # 팀별 윈도우당 실제 발송 상한
_FLOOD_WINDOW = 60.0          # 슬라이딩 윈도우(초)
_SUMMARY_COOLDOWN = 60.0      # 억제 요약 재발송 최소 간격(초)
_flood_lock = threading.Lock()
_flood_sent: dict[str, list] = {}   # team -> [최근 발송 epoch...]
_flood_supp: dict[str, list] = {}   # team -> [억제누적, 마지막요약 epoch]


def _flood_gate(team: str) -> tuple[bool, int, bool]:
    """발송 허용 판정. 반환=(허용?, 억제누적, 요약발송?)."""
    now = time.time()
    with _flood_lock:
        sent = _flood_sent.setdefault(team, [])
        cutoff = now - _FLOOD_WINDOW
        sent[:] = [t for t in sent if t > cutoff]
        if len(sent) < _FLOOD_MAX:
            sent.append(now)
            return True, 0, False
        supp = _flood_supp.setdefault(team, [0, 0.0])
        supp[0] += 1
        if now - supp[1] >= _SUMMARY_COOLDOWN:
            supp[1] = now
            n = supp[0]
            supp[0] = 0
            return False, n, True
        return False, supp[0], False


def _telegram_msg(ev, status: str, title: str, next_team: str, desc: str) -> str:
    """텔레그램 HTML 메시지(버튼 없음). 동적 값은 HTML 이스케이프."""
    e = _html.escape
    sev = _SEV_EMOJI.get(str(ev.severity), f"위험도 {e(str(ev.severity))}")
    return (
        f"🛡️ <b>[{e(ev.ticket_no or '-')}] {e(title)}</b>\n"
        f"• 시그니처: <code>{e(ev.signature or '-')}</code>\n"
        f"• 출발지: <code>{e(ev.src_ip or '-')}</code>  ·  {sev}\n"
        f"• 현재 상태: <b>{e(status)}</b>  (다음 담당: {e(next_team)})\n"
        f"• {e(desc)}\n"
        f"🕒 {_now_kst()} (KST)"
    )


def _telegram(team: str, html_text: str) -> tuple[bool, str]:
    """역할(team)의 텔레그램 chat(들)으로 발송. 쉼표로 여러 명 지정 가능. 미설정 시 드라이런."""
    token = config.TELEGRAM_BOT_TOKEN
    chats = [c.strip() for c in (config.TELEGRAM_CHAT.get(team) or "").split(",") if c.strip()]
    if not (token and chats):
        return True, f"드라이런(텔레그램 미설정·{team})"
    ok = 0
    for chat in chats:
        try:
            r = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat, "text": html_text, "parse_mode": "HTML",
                      "disable_web_page_preview": True},
                timeout=5,
            )
            r.raise_for_status()
            ok += 1
        except Exception:  # noqa: BLE001
            pass
    return (ok > 0), f"텔레그램→{team} {ok}/{len(chats)}명"

# 역할별 access_token 캐시: team -> (access_token, 만료 epoch)
_TOKEN_CACHE: dict[str, tuple[str, float]] = {}


def _access_token(team: str) -> str:
    """역할의 유효한 Kakao access_token을 반환. refresh_token이 있으면 자동 갱신."""
    direct = (config.KAKAO_TOKEN.get(team) or "").strip()
    if direct:
        return direct   # 고정 토큰(테스트용, ~6h)
    rt = (config.KAKAO_REFRESH.get(team) or "").strip()
    if not (rt and config.KAKAO_REST_KEY):
        return ""
    cached = _TOKEN_CACHE.get(team)
    if cached and cached[1] > time.time() + 60:
        return cached[0]
    try:
        data = {"grant_type": "refresh_token", "client_id": config.KAKAO_REST_KEY, "refresh_token": rt}
        if config.KAKAO_CLIENT_SECRET:   # 앱에 Client Secret '사용함'이면 필수
            data["client_secret"] = config.KAKAO_CLIENT_SECRET
        r = requests.post("https://kauth.kakao.com/oauth/token", data=data, timeout=8)
        r.raise_for_status()
        j = r.json()
        at = j.get("access_token", "")
        _TOKEN_CACHE[team] = (at, time.time() + int(j.get("expires_in", 21600)))
        return at
    except Exception:
        return ""


def _kst(dt) -> str:
    """UTC naive datetime → KST 문자열."""
    if not dt:
        return "-"
    try:
        return (dt + timedelta(hours=9)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return str(dt)


def _email_html(ev, status: str, title: str, next_team: str, desc: str, link: str) -> str:
    """단계 알림 HTML 메일 본문 — 모든 동적 값은 HTML 이스케이프."""
    e = _html.escape
    sev_label, sev_color = _SEV.get(str(ev.severity), ("정보", "#5b6b7a"))

    def row(label, value):
        return (f'<tr><td style="padding:7px 10px;color:#6b7280;background:#f8f9fb;'
                f'white-space:nowrap;border-bottom:1px solid #eef0f4;width:110px;">{e(label)}</td>'
                f'<td style="padding:7px 10px;color:#1b1c25;border-bottom:1px solid #eef0f4;">{value}</td></tr>')

    rows = [
        row("티켓번호", f'<b>{e(ev.ticket_no or "-")}</b>'),
        row("시그니처", e(ev.signature or "-")),
        row("위험도 / 우선순위",
            f'<span style="display:inline-block;background:{sev_color};color:#fff;border-radius:5px;'
            f'padding:1px 8px;font-size:12px;font-weight:700;">{e(sev_label)}</span>'
            f'&nbsp;·&nbsp;{e(ev.priority or "-")}'),
        row("출발지 → 목적지", f'{e(ev.src_ip or "-")} &rarr; {e(ev.dest_ip or "-")}'),
        row("현재 상태", f'<b>{e(status)}</b> &nbsp;(다음 담당: {e(next_team)})'),
        row("담당자", e(ev.assignee.display_name if ev.assignee else "미배정")),
        row("알림 시각", f'{_now_kst()} (KST)'),
    ]
    if ev.origin != "수동":
        rows.append(row("AI 판단",
                        f'{e(ev.ai_verdict or "-")} {ev.ai_confidence or 0}% · {e(ev.ai_attack_type or "-")}'))
    if ev.due_at:
        rows.append(row("SLA 기한", _kst(ev.due_at)))
    if ev.resolved_at:
        rows.append(row("종결", f'{e(ev.resolution_code or "-")} · {_kst(ev.resolved_at)}'))

    reason = ""
    if ev.ai_reasoning:
        reason = (f'<div style="margin-top:14px;padding:11px 13px;background:#f8f9fb;border-radius:8px;'
                  f'border:1px solid #eef0f4;font-size:12.5px;color:#3a3d46;line-height:1.6;">'
                  f'<b style="color:#6b7280;">AI 판단 근거</b><br>{e(ev.ai_reasoning)}</div>')

    return f"""\
<div style="background:#f1f2f6;padding:24px 12px;">
  <div style="max-width:580px;margin:0 auto;font-family:'Malgun Gothic','Apple SD Gothic Neo',sans-serif;">
    <div style="background:{sev_color};color:#fff;padding:16px 20px;border-radius:10px 10px 0 0;">
      <div style="font-size:12px;opacity:.85;letter-spacing:.3px;">SOC 내부 소통플랫폼 · 티켓 알림</div>
      <div style="font-size:18px;font-weight:700;margin-top:4px;">{e(title)}</div>
    </div>
    <div style="background:#fff;border:1px solid #e5e7eb;border-top:none;border-radius:0 0 10px 10px;padding:18px 20px;">
      <table style="width:100%;border-collapse:collapse;font-size:13px;border:1px solid #eef0f4;border-radius:8px;overflow:hidden;">
        {''.join(rows)}
      </table>
      {reason}
      <p style="font-size:13px;color:#3a3d46;margin:14px 0 16px;">{e(desc)}</p>
      <a href="{e(link)}" style="display:inline-block;background:#5b5bd6;color:#fff;text-decoration:none;
         padding:10px 22px;border-radius:8px;font-size:13px;font-weight:600;">티켓 열기 &rarr;</a>
      <div style="margin-top:18px;padding-top:12px;border-top:1px solid #eef0f4;font-size:11px;color:#9296a3;">
        본 메일은 SOC 티켓 프로세스 단계 전환 시 자동 발송되며 기록용으로 보관됩니다.
      </div>
    </div>
  </div>
</div>"""

# 단계(status) → (제목, 다음 담당 팀, 설명)
_STAGE_INFO: dict[str, tuple[str, str, str]] = {
    "미접수": ("새 정탐 티켓 수신", "보안관제팀", "분석플랫폼에서 정탐 이벤트가 접수됨 — 관제팀 확인 필요"),
    "접수": ("티켓 접수", "보안관제팀", "보안관제팀이 티켓을 접수함"),
    "검토": ("정탐 판정 · 정보보호 검토 이관", "정보보호팀", "관제팀 정탐 판정 → 정보보호 담당자 검토 이관"),
    "대응": ("대응 진행", "웹관리자", "정보보호 담당자가 대응을 배정/진행"),
    "승인대기": ("대응 완료 · 최종 승인 요청", "정보보호팀", "대응 완료 — 정보보호 담당자 최종 승인 필요"),
    "오탐요청": ("오탐 종결 승인 요청", "정보보호팀", "관제팀이 오탐 종결을 요청 — 정보보호 승인 필요"),
    "무시종결요청": ("무시 종결 승인 요청", "정보보호팀", "관제팀이 무시 종결을 요청 — 정보보호 승인 필요"),
    "종결": ("티켓 종결", "보안관제팀", "정보보호 담당자가 최종 종결함"),
    "오탐종결": ("오탐 종결", "보안관제팀", "정보보호 담당자가 오탐으로 종결함"),
    "무시종결": ("무시 종결", "보안관제팀", "정보보호 담당자가 무시(오탐·중복) 종결함"),
}


def _kakao(team: str, text: str, link: str) -> tuple[bool, str]:
    """해당 역할(team)의 카톡으로 발송. 미설정 시 드라이런."""
    to = (config.KAKAO_TO.get(team) or "").strip()
    token = (config.KAKAO_TOKEN.get(team) or "").strip()
    # (1) 웹훅/제공사 중계 — 역할별 수신자(to) 포함
    if config.KAKAO_NOTIFY_URL and to:
        try:
            headers = {"Content-Type": "application/json"}
            if config.KAKAO_NOTIFY_AUTH:
                headers["Authorization"] = config.KAKAO_NOTIFY_AUTH
            payload = {"to": to, config.KAKAO_NOTIFY_FIELD: text, "link": link, "team": team}
            r = requests.post(config.KAKAO_NOTIFY_URL, json=payload, headers=headers, timeout=8)
            r.raise_for_status()
            return True, f"카톡(웹훅)→{team}"
        except Exception as exc:  # noqa: BLE001
            return False, f"카톡(웹훅·{team}) 실패: {exc}"
    # (2) 역할별 Kakao 토큰('나에게 보내기') — 피드 템플릿(카드형) + 버튼 제거
    token = token or _access_token(team)
    if token:
        try:
            lines = text.split("\n")
            f_title = lines[0][:200] or "SOC 티켓 알림"
            f_desc = ("\n".join(lines[1:]).strip() or " ")[:1000]
            tmpl = {
                "object_type": "feed",
                "content": {
                    "title": f_title,
                    "description": f_desc,
                    "link": {"web_url": link, "mobile_web_url": link},
                },
                "buttons": [],   # '자세히 보기' 기본 버튼 제거
            }
            r = requests.post(
                "https://kapi.kakao.com/v2/api/talk/memo/default/send",
                headers={"Authorization": f"Bearer {token}"},
                data={"template_object": json.dumps(tmpl, ensure_ascii=False)},
                timeout=8,
            )
            r.raise_for_status()
            return True, f"카톡(피드)→{team}"
        except Exception as exc:  # noqa: BLE001
            return False, f"카톡(memo·{team}) 실패: {exc}"
    return True, f"드라이런(카톡 미설정·{team})"


def _kakao_phone(phone: str, text: str, link: str) -> bool:
    """가입 시 등록된 전화번호로 카톡(제공사/중계 웹훅) 발송."""
    if not config.KAKAO_NOTIFY_URL:
        return False
    try:
        headers = {"Content-Type": "application/json"}
        if config.KAKAO_NOTIFY_AUTH:
            headers["Authorization"] = config.KAKAO_NOTIFY_AUTH
        payload = {"to": phone, config.KAKAO_NOTIFY_FIELD: text, "link": link}
        r = requests.post(config.KAKAO_NOTIFY_URL, json=payload, headers=headers, timeout=8)
        r.raise_for_status()
        return True
    except Exception:  # noqa: BLE001
        return False


def _consented_users(db, team: str) -> list:
    """해당 팀에서 '수신 동의'한 사용자(가입 시 등록한 연락처) 목록."""
    from models import User
    return [u for u in db.query(User).filter(User.team == team).all() if u.notify_consent]


def notify_stage(db, ev, status: str, actor_id: int | None = None, note: str = "") -> None:
    """티켓이 status로 전이될 때 '해당 단계 담당 역할'의 카톡+이메일로 알리고 기록한다.

    수신처 우선순위: ① 그 팀에서 수신동의한 사용자(가입 시 등록 연락처) → ② .env 설정값 폴백.
    note에 '반려'가 들어오면(정보보호 반려 등) 반려 알림으로 표시하고 사유를 함께 보낸다.
    """
    info = _STAGE_INFO.get(status)
    if not info or not config.NOTIFY_ENABLED:
        return
    title, next_team, desc = info
    # 반려로 되돌아온 경우 — 제목/설명을 '반려'로 표시하고 사유 포함
    is_reject = bool(note) and "반려" in note
    if is_reject:
        title = f"⛔ 반려 — 재처리 필요 ({status} 단계)"
        desc = note   # 예: "반려 사유: 대응 증적 부족"
    # '대응' 단계: 정보보호 직접 처리면 외부 알림 불필요(본인이 처리), 웹관리자 위임이면 웹관리자에게
    if status == "대응":
        if ev.assignee and getattr(ev.assignee, "team", "") == "정보보호팀" and not is_reject:
            return
        next_team = "웹관리자"

    # ── 자기 행동을 자기 팀에 다시 알리지 않음(예: 관제가 '접수' → 관제 알림 불필요) ──
    # 팀이 바뀌는 인계(검토→정보보호, 대응→웹관리자, 승인→정보보호 등)만 알린다.
    if actor_id and not is_reject:
        actor = db.get(User, actor_id)
        if actor and getattr(actor, "team", "") == next_team:
            return

    # ── 폭주 가드: 단시간 대량 알림이면 개별 발송을 멈추고 요약 1건으로 대체 ──
    allow, supp_n, do_summary = _flood_gate(next_team)
    if not allow:
        if do_summary:   # 윈도우당 1회만, 억제된 건수를 요약 통지
            warn = (f"⚠️ <b>알림 폭주 감지</b>\n"
                    f"최근 1분간 <b>{_html.escape(next_team)}</b> 대상 알림 "
                    f"<b>{supp_n}건</b>을 억제했습니다 (DDoS·스캔 의심).\n"
                    f"플랫폼 티켓 목록에서 일괄 확인하세요.")
            if config.TELEGRAM_BOT_TOKEN:
                _telegram(next_team, warn)
            db.add(EventHistory(
                event_id=ev.id, user_id=actor_id, action="알림",
                detail=f"[폭주 억제→{next_team}] 최근 1분 {supp_n}건 발송 생략 · 요약 1건 통지",
            ))
            db.commit()
        # 개별 억제 건은 이력/네트워크 부하 최소화를 위해 발송·기록 생략
        return

    link = f"{config.COMM_BASE_URL}/events"   # 카톡 카드/메일 버튼용(클릭 불필요해도 API상 유지)
    # 메시지 본문에는 링크를 넣지 않고 '정보만' — 접속 없이 폰에서 상황 파악 가능
    msg = (
        f"[SOC 티켓 {ev.ticket_no}] {title}\n"
        f"· 시그니처: {ev.signature}\n"
        f"· 출발지: {ev.src_ip or '-'}  위험도: {ev.severity}\n"
        f"· 현재 상태: {status}  (다음 담당: {next_team})\n"
        f"· {desc}\n"
        f"🕒 {_now_kst()} (KST)"
    )

    subject = f"[{ev.ticket_no}] {title}"

    # 1) 모바일 푸시 — 텔레그램(역할 라우팅). 토큰 없으면 카톡으로 폴백.
    if config.TELEGRAM_BOT_TOKEN:
        _ok, push_info = _telegram(next_team, _telegram_msg(ev, status, title, next_team, desc))
    else:
        _k_ok, push_info = _kakao(next_team, msg, link)

    # 2) 메일 — 텔레그램과 동일한 역할 라우팅으로 janus.com 사서함에 실제 발송(HTML)
    to_list = [a.strip() for a in (config.NOTIFY_MAIL_TO.get(next_team) or "").split(",") if a.strip()]
    if to_list and config.MAIL_GATEWAY_HOST:
        html_body = _email_html(ev, status, title, next_team, desc, link)
        sent = sum(1 for to in to_list
                   if mail_gateway.send_mail(config.NOTIFY_MAIL_FROM, "", to, subject, msg, html=html_body)[0])
        e_info = f"메일→{next_team} {sent}/{len(to_list)}건"
    else:
        e_info = "메일 미설정"

    # 3) 처리 이력에 알림 결과 기록
    db.add(EventHistory(
        event_id=ev.id, user_id=actor_id, action="알림",
        detail=f"[{title}→{next_team}] 푸시: {push_info} / {e_info}",
    ))
    db.commit()
