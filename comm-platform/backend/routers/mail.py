"""메일 — janus.com 사용자별 사서함(webmail). 받기(IMAP) / 보내기(SMTP) / 안읽음.

인앱 메일·사내부서(SMTP 더미) 발송은 janus.com 실메일로 통합되어 제거됨.
(플랫폼 내부 메시지는 DM 기능 사용. 티켓 단계 알림 메일 기록은 notify_service가 별도 유지.)
"""
import uuid
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

import config
import mail_gateway
from db import get_db
from models import User

router = APIRouter(prefix="/api/mail", tags=["mail"])

# 첨부 발송 staging(웹 비공개) — 업로드→발송 사이 임시 저장
_ATT_DIR = Path(config.UPLOAD_DIR).parent / "mail_staging"
_ATT_DIR.mkdir(parents=True, exist_ok=True)
_ATT_MAX = 10 * 1024 * 1024  # 10MB/파일
_ATT_BLOCK = {"exe", "bat", "cmd", "scr", "com", "msi", "js", "vbs", "ps1", "jar", "dll"}


def _mail_user(db: Session, user_id: int) -> User:
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    if not (u.mail_address and u.mail_password):
        raise HTTPException(status_code=400, detail="이 계정에 연결된 janus.com 사서함이 없습니다.")
    return u


class AttachmentIn(BaseModel):
    token: str          # 업로드 staging 토큰
    name: str           # 원본 파일명


class ExternalSendIn(BaseModel):
    user_id: int
    to: str
    subject: str
    body: str = ""
    attachments: list[AttachmentIn] = []
    in_reply_to: str = ""        # 회신 시 원본 Message-ID(스레딩)


class MarkReadIn(BaseModel):
    user_id: int
    uid: str


class TrashIn(BaseModel):
    user_id: int
    uid: str
    source: str = "inbox"   # inbox | sent


class RestoreIn(BaseModel):
    user_id: int
    uid: str


class PurgeIn(BaseModel):
    user_id: int
    uid: str | None = None  # None이면 휴지통 전체 비우기


@router.post("/external/read")
def external_read(req: MarkReadIn, db: Session = Depends(get_db)) -> dict:
    """메일을 읽음(\\Seen)으로 표시 → 안읽음 배지 감소."""
    u = _mail_user(db, req.user_id)
    return {"ok": mail_gateway.mark_seen(u.mail_address, u.mail_password, req.uid)}


@router.get("/unread_count")
def unread_count(user_id: int = Query(...), db: Session = Depends(get_db)) -> dict:
    """janus.com 받은편지함 안읽음(UNSEEN) 수. 사서함 없으면 0."""
    u = db.get(User, user_id)
    if not u or not (u.mail_address and u.mail_password):
        return {"unread": 0}
    return {"unread": mail_gateway.unseen_count(u.mail_address, u.mail_password)}


@router.get("/external/account")
def external_account(user_id: int = Query(...), db: Session = Depends(get_db)) -> dict:
    """이 사용자에게 연결된 사서함 주소 + 인증 가능 여부."""
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    if not (u.mail_address and u.mail_password):
        return {"address": u.mail_address or "", "linked": False}
    ok, info = mail_gateway.verify_account(u.mail_address, u.mail_password)
    return {"address": u.mail_address, "linked": ok, "detail": info}


@router.get("/external/inbox")
def external_inbox(user_id: int = Query(...), limit: int = Query(30),
                   db: Session = Depends(get_db)) -> dict:
    """본인 janus.com 받은편지함(외부 신뢰불가 콘텐츠 — 본문은 텍스트로 표시)."""
    u = _mail_user(db, user_id)
    try:
        msgs = mail_gateway.fetch_mailbox(u.mail_address, u.mail_password, "INBOX", limit)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"메일 서버 조회 실패: {exc}")
    return {"address": u.mail_address, "count": len(msgs), "messages": msgs}


@router.get("/external/sent")
def external_sent(user_id: int = Query(...), limit: int = Query(30),
                  db: Session = Depends(get_db)) -> dict:
    u = _mail_user(db, user_id)
    msgs = mail_gateway.fetch_sent(u.mail_address, u.mail_password, limit)
    return {"address": u.mail_address, "count": len(msgs), "messages": msgs}


@router.get("/external/trash")
def external_trash_list(user_id: int = Query(...), limit: int = Query(30),
                        db: Session = Depends(get_db)) -> dict:
    """본인 사서함 휴지통 목록."""
    u = _mail_user(db, user_id)
    msgs = mail_gateway.fetch_trash(u.mail_address, u.mail_password, limit)
    return {"address": u.mail_address, "count": len(msgs), "messages": msgs}


@router.post("/external/trash")
def external_trash_move(req: TrashIn, db: Session = Depends(get_db)) -> dict:
    """받은/보낸 편지함의 메일을 휴지통으로 이동."""
    u = _mail_user(db, req.user_id)
    if not mail_gateway.move_to_trash(u.mail_address, u.mail_password, req.uid, req.source):
        raise HTTPException(status_code=502, detail="메일을 휴지통으로 옮기지 못했습니다.")
    return {"ok": True}


@router.post("/external/restore")
def external_restore(req: RestoreIn, db: Session = Depends(get_db)) -> dict:
    """휴지통의 메일을 받은편지함으로 복원."""
    u = _mail_user(db, req.user_id)
    if not mail_gateway.restore_from_trash(u.mail_address, u.mail_password, req.uid):
        raise HTTPException(status_code=502, detail="메일을 복원하지 못했습니다.")
    return {"ok": True}


@router.post("/external/purge")
def external_purge(req: PurgeIn, db: Session = Depends(get_db)) -> dict:
    """휴지통에서 영구 삭제(uid 1건) 또는 전체 비우기(uid 없음)."""
    u = _mail_user(db, req.user_id)
    if not mail_gateway.purge_trash(u.mail_address, u.mail_password, req.uid):
        raise HTTPException(status_code=502, detail="영구 삭제에 실패했습니다.")
    return {"ok": True}


@router.post("/upload")
async def mail_upload(file: UploadFile = File(...)) -> dict:
    """첨부 파일 업로드(staging). 발송 시 token으로 참조한다."""
    data = await file.read()
    if len(data) > _ATT_MAX:
        raise HTTPException(status_code=400, detail="파일이 너무 큽니다 (최대 10MB).")
    fname = file.filename or "attachment"
    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    if ext in _ATT_BLOCK:
        raise HTTPException(status_code=400, detail="실행 파일은 첨부할 수 없습니다.")
    token = uuid.uuid4().hex
    (_ATT_DIR / token).write_bytes(data)
    return {"token": token, "name": fname, "size": len(data)}


@router.post("/external/send")
def external_send(req: ExternalSendIn, db: Session = Depends(get_db)) -> dict:
    """본인 주소(From=janus.com 사서함)로 발송. 첨부(token 참조) 포함."""
    u = _mail_user(db, req.user_id)
    if not req.to.strip():
        raise HTTPException(status_code=400, detail="받는 사람을 입력하세요.")
    if not req.subject.strip():
        raise HTTPException(status_code=400, detail="제목을 입력하세요.")
    # staging 토큰 → 실제 바이트
    atts, used = [], []
    for a in req.attachments:
        fp = _ATT_DIR / Path(a.token).name           # 경로 조작 방지
        if fp.exists():
            atts.append({"name": a.name, "data": fp.read_bytes()})
            used.append(fp)
    ok, info = mail_gateway.send_mail(u.mail_address, u.mail_password,
                                      req.to.strip(), req.subject, req.body, attachments=atts,
                                      in_reply_to=(req.in_reply_to or "").strip() or None)
    for fp in used:                                   # 발송 후 staging 정리
        try:
            fp.unlink()
        except Exception:
            pass
    if not ok:
        raise HTTPException(status_code=502, detail=info)
    return {"ok": True, "from": u.mail_address, "to": req.to.strip(),
            "detail": info, "attached": len(atts)}


@router.get("/external/attachment")
def external_attachment(user_id: int = Query(...), uid: str = Query(...),
                        idx: int = Query(0), source: str = Query("inbox"),
                        db: Session = Depends(get_db)) -> Response:
    """수신 메일의 첨부 1건 다운로드."""
    u = _mail_user(db, user_id)
    res = mail_gateway.fetch_attachment(u.mail_address, u.mail_password, uid, source, idx)
    if not res:
        raise HTTPException(status_code=404, detail="첨부를 찾을 수 없습니다.")
    name, ctype, data = res
    disp = f"attachment; filename*=UTF-8''{quote(name)}"
    return Response(content=data, media_type=ctype or "application/octet-stream",
                    headers={"Content-Disposition": disp})
