"""채널 기반 채팅 (REST 저장 + WebSocket 실시간 브로드캐스트)."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from db import get_db
from models import Channel, ChatMessage, Event, User
from realtime import manager
from schemas import ChannelOut, ChatMessageIn, ChatMessageOut
from timeutil import kst_iso

router = APIRouter(prefix="/api/chat", tags=["chat"])


@router.get("/channels", response_model=list[ChannelOut])
def list_channels(db: Session = Depends(get_db)) -> list[Channel]:
    return list(db.scalars(select(Channel).order_by(Channel.id)))


@router.get("/channels/{channel_id}/messages", response_model=list[ChatMessageOut])
def list_messages(
    channel_id: int,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
) -> list[ChatMessage]:
    stmt = (
        select(ChatMessage)
        .where(ChatMessage.channel_id == channel_id)
        .order_by(ChatMessage.created_at.desc())
        .limit(limit)
    )
    rows = list(db.scalars(stmt))
    return list(reversed(rows))  # 오래된 → 최신 순으로 반환


def _event_card(ev: Event | None) -> dict | None:
    if not ev:
        return None
    return {
        "id": ev.id, "signature": ev.signature, "severity": ev.severity,
        "src_ip": ev.src_ip, "ai_verdict": ev.ai_verdict,
        "ai_attack_type": ev.ai_attack_type, "ai_confidence": ev.ai_confidence,
        "status": ev.status,
    }


@router.post("/channels/{channel_id}/messages", response_model=ChatMessageOut)
async def send_message(
    channel_id: int, req: ChatMessageIn, db: Session = Depends(get_db)
) -> ChatMessage:
    if not db.get(Channel, channel_id):
        raise HTTPException(status_code=404, detail="채널을 찾을 수 없습니다.")
    user = db.get(User, req.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")
    if not req.body.strip() and not req.image_url:
        raise HTTPException(status_code=400, detail="메시지 또는 이미지를 입력하세요.")
    event_id = req.event_id if req.event_id and db.get(Event, req.event_id) else None
    msg = ChatMessage(channel_id=channel_id, user_id=req.user_id, body=req.body,
                      event_id=event_id, image_url=req.image_url)
    db.add(msg)
    db.commit()
    db.refresh(msg)

    await manager.broadcast({
        "type": "chat_message",
        "channel_id": channel_id,
        "message": {
            "id": msg.id, "channel_id": channel_id, "body": msg.body,
            "image_url": msg.image_url,
            "created_at": kst_iso(msg.created_at),
            "user": {"id": user.id, "display_name": user.display_name,
                     "team": user.team, "username": user.username, "role": user.role},
            "event": _event_card(msg.event),
        },
    })
    return msg
