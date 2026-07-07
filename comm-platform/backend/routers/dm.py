"""1:1 다이렉트 메시지 — 대화 목록(스레드) / 대화 조회 / 전송."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from db import get_db
from models import DirectMessage, User
from realtime import manager
from schemas import DMIn, DMOut, DMThread
from timeutil import kst_iso

router = APIRouter(prefix="/api/dm", tags=["dm"])


def _u(u: User) -> dict:
    return {"id": u.id, "display_name": u.display_name, "team": u.team,
            "username": u.username, "role": u.role}


@router.get("/threads", response_model=list[DMThread])
def threads(user_id: int = Query(...), db: Session = Depends(get_db)) -> list[dict]:
    """나와 대화한 상대별 최근 메시지 + 안읽음 수."""
    rows = list(db.scalars(
        select(DirectMessage)
        .where(or_(DirectMessage.sender_id == user_id, DirectMessage.recipient_id == user_id))
        .order_by(DirectMessage.created_at.desc())
    ))
    seen: dict[int, dict] = {}
    for m in rows:
        partner_id = m.recipient_id if m.sender_id == user_id else m.sender_id
        if partner_id not in seen:
            partner = db.get(User, partner_id)
            if not partner:
                continue
            seen[partner_id] = {"partner": _u(partner), "last_body": m.body,
                                "last_at": m.created_at, "unread": 0}
        if m.recipient_id == user_id and not m.is_read:
            seen[partner_id]["unread"] += 1
    return list(seen.values())


@router.get("/conversation", response_model=list[DMOut])
def conversation(
    user_id: int = Query(...), other_id: int = Query(...), db: Session = Depends(get_db)
) -> list[DirectMessage]:
    """두 사람 간 대화 전체(시간순). 조회 시 받은 메시지는 읽음 처리."""
    stmt = (
        select(DirectMessage)
        .where(or_(
            (DirectMessage.sender_id == user_id) & (DirectMessage.recipient_id == other_id),
            (DirectMessage.sender_id == other_id) & (DirectMessage.recipient_id == user_id),
        ))
        .order_by(DirectMessage.created_at)
    )
    msgs = list(db.scalars(stmt))
    changed = False
    for m in msgs:
        if m.recipient_id == user_id and not m.is_read:
            m.is_read = True
            changed = True
    if changed:
        db.commit()
    return msgs


@router.get("/unread_count")
def unread_count(user_id: int = Query(...), db: Session = Depends(get_db)) -> dict:
    n = db.scalar(
        select(func.count()).select_from(DirectMessage)
        .where(DirectMessage.recipient_id == user_id, DirectMessage.is_read == False)  # noqa: E712
    )
    return {"unread": n or 0}


@router.post("", response_model=DMOut)
async def send_dm(req: DMIn, db: Session = Depends(get_db)) -> DirectMessage:
    if not db.get(User, req.recipient_id):
        raise HTTPException(status_code=404, detail="수신자를 찾을 수 없습니다.")
    if req.sender_id == req.recipient_id:
        raise HTTPException(status_code=400, detail="자기 자신에게는 보낼 수 없습니다.")
    if not req.body.strip() and not req.image_url:
        raise HTTPException(status_code=400, detail="메시지 또는 이미지를 입력하세요.")
    m = DirectMessage(sender_id=req.sender_id, recipient_id=req.recipient_id,
                      body=req.body, image_url=req.image_url)
    db.add(m)
    db.commit()
    db.refresh(m)
    # 비공개 메시지 — 발신자·수신자 소켓에만 전송 (전체 브로드캐스트 X)
    await manager.send_to_users({m.sender_id, m.recipient_id}, {
        "type": "dm",
        "sender_id": m.sender_id,
        "recipient_id": m.recipient_id,
        "message": {
            "id": m.id, "body": m.body, "image_url": m.image_url, "is_read": m.is_read,
            "created_at": kst_iso(m.created_at),
            "sender": _u(m.sender), "recipient": _u(m.recipient),
        },
    })
    return m
