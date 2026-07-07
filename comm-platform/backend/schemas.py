"""Pydantic 요청/응답 스키마."""
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, PlainSerializer

# DB에는 UTC(naive)로 저장 → 응답 시 Asia/Seoul(+09:00)로 변환해 내려준다.
_KST = timezone(timedelta(hours=9))


def _to_kst_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_KST).isoformat()


# 모든 응답 datetime에 사용하는 KST 직렬화 타입
KSTDateTime = Annotated[datetime, PlainSerializer(_to_kst_iso, return_type=str)]


class _ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ── 사용자 ──
class UserOut(_ORM):
    id: int
    username: str
    display_name: str
    team: str
    role: str
    mail_address: str = ""


class LoginIn(BaseModel):
    username: str
    password: str


class SignupIn(BaseModel):
    username: str
    password: str
    display_name: str
    team: str
    role: str = "분석가"
    mail_local: str = ""     # janus.com 사서함 앞부분(비우면 username 사용)
    email: str = ""
    phone: str = ""
    notify_consent: bool = False


# ── 이벤트 ──
class IngestEvent(BaseModel):
    """분석플랫폼 → 소통플랫폼 정탐 이벤트 수신 페이로드."""
    signature: str
    src_ip: str = ""
    dest_ip: str = ""
    src_port: str = ""
    dest_port: str = ""
    asset: str = ""
    uri: str = ""
    payload: str = ""
    severity: str = "2"
    source: str = ""
    detected_at: str = ""
    ai_verdict: str = "정탐"
    ai_confidence: int = 0
    ai_attack_type: str = ""
    ai_reasoning: str = ""
    mitre: str = ""          # 상관룰이 큐레이션한 MITRE(있으면 권위값으로 사용)
    dup_count: int = 1


class IngestBatch(BaseModel):
    events: list[IngestEvent]


class CommentIn(BaseModel):
    user_id: int
    body: str


class CommentOut(_ORM):
    id: int
    body: str
    created_at: KSTDateTime
    user: UserOut


class HistoryOut(_ORM):
    id: int
    action: str
    detail: str
    created_at: KSTDateTime
    user: UserOut | None


class AttachmentOut(_ORM):
    id: int
    url: str
    name: str
    size: int
    created_at: KSTDateTime
    uploaded_by: UserOut | None


class TaskOut(_ORM):
    id: int
    title: str
    done: bool
    created_at: KSTDateTime


class EventOut(_ORM):
    id: int
    ticket_no: str
    signature: str
    src_ip: str
    dest_ip: str
    src_port: str = ""
    dest_port: str = ""
    asset: str = ""
    uri: str
    payload: str = ""
    severity: str
    priority: str
    source: str
    origin: str
    tags: str
    mitre: str
    detected_at: str
    due_at: KSTDateTime | None
    resolved_at: KSTDateTime | None
    resolution_code: str
    root_cause: str
    ai_verdict: str
    ai_confidence: int
    ai_attack_type: str
    ai_reasoning: str
    dup_count: int
    status: str
    assignee: UserOut | None
    created_at: KSTDateTime
    updated_at: KSTDateTime


class EventDetail(EventOut):
    comments: list[CommentOut]
    history: list[HistoryOut]
    attachments: list[AttachmentOut]
    tasks: list[TaskOut]


class TaskIn(BaseModel):
    user_id: int
    title: str


class TaskToggle(BaseModel):
    user_id: int
    done: bool


class ManualTicketIn(BaseModel):
    user_id: int
    signature: str                 # 제목/유형
    severity: str = "2"
    priority: str | None = None    # 미지정 시 severity로 자동
    src_ip: str = ""
    dest_ip: str = ""
    src_port: str = ""
    dest_port: str = ""
    uri: str = ""
    description: str = ""          # 상황 설명 → ai_reasoning
    attack_type: str = ""
    tags: str = ""
    mitre: str = ""


class PriorityUpdate(BaseModel):
    user_id: int
    priority: str


class MetaUpdate(BaseModel):
    user_id: int
    tags: str | None = None
    mitre: str | None = None


class AttachmentIn(BaseModel):
    user_id: int
    url: str
    name: str = ""
    size: int = 0


class StatusUpdate(BaseModel):
    user_id: int
    status: str
    note: str = ""
    resolution_code: str = ""    # 종결 시
    root_cause: str = ""


class AssignUpdate(BaseModel):
    user_id: int          # 작업 수행자
    assignee_id: int | None


# ── 채팅 ──
class ChannelOut(_ORM):
    id: int
    name: str
    description: str


class EventCard(_ORM):
    """채팅에서 공유되는 이벤트 요약 카드."""
    id: int
    signature: str
    severity: str
    src_ip: str
    ai_verdict: str
    ai_attack_type: str
    ai_confidence: int
    status: str


class ChatMessageIn(BaseModel):
    user_id: int
    body: str = ""
    event_id: int | None = None
    image_url: str | None = None


class ChatMessageOut(_ORM):
    id: int
    channel_id: int
    body: str
    image_url: str | None = None
    created_at: KSTDateTime
    user: UserOut
    event: EventCard | None = None


# ── 다이렉트 메시지 (1:1) ──
class DMIn(BaseModel):
    sender_id: int
    recipient_id: int
    body: str = ""
    image_url: str | None = None


class DMOut(_ORM):
    id: int
    body: str
    image_url: str | None = None
    is_read: bool
    created_at: KSTDateTime
    sender: UserOut
    recipient: UserOut


class DMThread(BaseModel):
    partner: UserOut
    last_body: str
    last_at: KSTDateTime | None
    unread: int


# ── IOC (침해지표) ──
class IOCIn(BaseModel):
    ioc_type: str
    value: str
    severity: str = "2"
    confidence: int = 50
    status: str = "활성"
    description: str = ""
    source_event_id: int | None = None
    created_by_id: int | None = None
    first_seen: str = ""
    last_seen: str = ""


class IOCUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    confidence: int | None = None
    description: str | None = None


class IOCOut(_ORM):
    id: int
    ioc_type: str
    value: str
    severity: str
    confidence: int
    status: str
    description: str
    source_event_id: int | None
    first_seen: str
    last_seen: str
    created_at: KSTDateTime
    updated_at: KSTDateTime
    created_by: UserOut | None


# ── 메일 ──
class MailIn(BaseModel):
    sender_id: int
    recipient_id: int | None = None          # 플랫폼 사용자(인앱)
    recipient_email: str = ""                # 외부 부서(이메일)
    recipient_name: str = ""
    recipient_dept: str = ""
    subject: str
    body: str
    related_event_id: int | None = None


class MailOut(_ORM):
    id: int
    subject: str
    body: str
    is_read: bool
    channel: str
    recipient_email: str
    recipient_name: str
    recipient_dept: str
    related_event_id: int | None
    created_at: KSTDateTime
    sender: UserOut
    recipient: UserOut | None


# ── 연락처(주소록) ──
class ContactIn(BaseModel):
    name: str
    email: str
    dept: str = ""
    note: str = ""


class ContactOut(_ORM):
    id: int
    name: str
    email: str
    dept: str
    note: str
    created_at: KSTDateTime
