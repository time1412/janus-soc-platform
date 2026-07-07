"""소통플랫폼 ORM 모델.

보안관제팀 ↔ 정보보호팀이 분석플랫폼에서 정탐으로 판정된 이벤트를
함께 검토/승인하고, 채팅·메일로 소통한다.
"""
import re
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Integer, String, Text, text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


# 티켓 라이프사이클(정보보안 관제 프로세스):
#   이벤트 발생 → 미접수 → 접수(보안관제) → [정탐 판정] 검토(정보보호 이관)
#       검토 →┬ 웹관리자 대응 필요: 대응(웹관리자) → 승인대기 → 종결(정보보호)
#             └ 정보보호 직접 처리: 대응(정보보호) ─────────────→ 종결(정보보호)
#       (오탐: 오탐요청 → 오탐종결 / 오탐·중복: 무시종결요청 → 무시종결, 모두 정보보호 최종 승인)
#   ※ 관제팀은 접수·정/오탐 판정만, 대응 배정과 최종 종결은 정보보호 담당자가 결정.
EVENT_STATUSES = ["미접수", "접수", "검토", "대응", "승인대기", "오탐요청", "무시종결요청", "종결", "오탐종결", "무시종결"]

# 권한(소속) — 각 처리 단계의 담당
#   보안관제팀: 접수·정/오탐 판정·무시종결 | 웹관리자: 대응 | 정보보호팀: 최종 승인(종결)·오탐종결
TEAMS = ["보안관제팀", "웹관리자", "정보보호팀"]

# 구버전 상태 → 신버전 상태 매핑(마이그레이션용)
LEGACY_STATUS_MAP = {
    "대기": "미접수", "검토중": "접수", "승인": "종결", "조치완료": "종결",
    "배정": "접수", "진행": "대응", "보류": "대응", "종료": "종결",
    "신규": "미접수", "판정": "접수", "완료": "종결", "반려": "오탐종결",
}

# 티켓 우선순위 + SLA(기한, 시간 단위)
PRIORITIES = ["P1", "P2", "P3", "P4"]
SLA_HOURS = {"P1": 1, "P2": 4, "P3": 24, "P4": 72}

# 최종 승인(종결) 시 판정/조치 결과 + 종결(닫힘) 상태
RESOLUTION_CODES = ["정탐/조치완료", "정탐/조치불요", "과탐/예외처리"]
TERMINAL_STATUSES = ["종결", "오탐종결", "무시종결"]


# 공격 유형별 기본 태그·MITRE ATT&CK 자동 부여 (수신/생성 시 비어 있으면 채움)
_DEFAULT_META = [
    (("sql",), "SQLi,웹공격,인젝션", "T1190"),
    (("xss", "cross", "script"), "XSS,웹공격", "T1059.007"),
    (("rce", "remote code", "command"), "RCE,명령실행,웹공격", "T1190,T1059"),
    (("lfi", "rfi", "traversal", "path", "inclusion", "passwd"), "경로조작,파일포함,웹공격", "T1083"),
    (("brute", "failed password", "invalid user"), "브루트포스,인증공격", "T1110"),
    (("scan", "nmap", "recon", "sweep"), "정찰,포트스캔", "T1046"),
    (("upload", "webshell"), "웹쉘,업로드", "T1505.003"),
    (("ddos", "flood", "denial"), "가용성,DDoS", "T1498"),
    (("session", "fixation"), "세션,인증", "T1539"),
]


def default_meta_for(text: str) -> tuple[str, str]:
    """공격 유형/시그니처 텍스트로 (기본 태그, 기본 MITRE 기법)을 추론한다."""
    s = (text or "").lower()
    for keys, tags, mitre in _DEFAULT_META:
        if any(k in s for k in keys):
            return tags, mitre
    return "웹공격", "T1190"


_MITRE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def mitre_ids(text: str) -> str:
    """자유 텍스트(상관룰 mitre, 예: 'T1539 Steal Web Session Cookie', 'T1498/T1499')에서
    MITRE 기법 ID만 추출해 콤마로 잇는다. ID가 없으면 ''(→ 키워드 추론 폴백)."""
    out: list[str] = []
    for m in _MITRE_ID_RE.findall(text or ""):
        u = m.upper()
        if u not in out:
            out.append(u)
    return ",".join(out)

def priority_from_severity(sev: str) -> str:
    return {"3": "P1", "2": "P2", "1": "P3"}.get(str(sev), "P3")

# IOC(침해지표)
IOC_TYPES = ["IP", "도메인", "URL", "해시", "이메일", "기타"]
IOC_STATUSES = ["활성", "차단완료", "만료", "오탐제외"]

# 사내 부서 (메일 수신 대상)
DEPARTMENTS = [
    "개발팀", "인프라팀", "운영팀", "DBA팀",
    "경영지원팀", "고객지원팀", "법무팀", "정보보호팀", "보안관제팀",
]


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(64))
    team: Mapped[str] = mapped_column(String(32))            # 보안관제팀 / 정보보호팀
    role: Mapped[str] = mapped_column(String(32), default="분석가")
    password: Mapped[str] = mapped_column(String(128), default="1234")  # 데모용 평문(추후 해시)
    # 알림 연락처(가입 시 수집) — 단계별 카톡/메일 발송에 사용
    email: Mapped[str] = mapped_column(String(255), default="", server_default=text("''"))
    phone: Mapped[str] = mapped_column(String(32), default="", server_default=text("''"))
    notify_consent: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("0"))
    # janus.com 사서함(웹메일 연동) — 가입 시 <username>@janus.com, 메일 비번=로그인 비번
    mail_address: Mapped[str] = mapped_column(String(255), default="", server_default=text("''"))
    mail_password: Mapped[str] = mapped_column(String(128), default="", server_default=text("''"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Event(Base):
    """분석플랫폼에서 정탐으로 판정돼 넘어온 보안 이벤트."""
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    # 원본 탐지 정보
    signature: Mapped[str] = mapped_column(String(255))
    src_ip: Mapped[str] = mapped_column(String(64), default="")
    dest_ip: Mapped[str] = mapped_column(String(64), default="")
    src_port: Mapped[str] = mapped_column(String(8), default="", server_default=text("''"))    # 출발지 포트
    dest_port: Mapped[str] = mapped_column(String(8), default="", server_default=text("''"))   # 목적지 포트
    asset: Mapped[str] = mapped_column(String(128), default="", server_default=text("''"))  # 호스트형 탐지 피해 자산
    uri: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))  # 판정에 쓰인 실제 공격 페이로드
    severity: Mapped[str] = mapped_column(String(8), default="2")
    source: Mapped[str] = mapped_column(String(32), default="")
    detected_at: Mapped[str] = mapped_column(String(40), default="")  # 원본 _time
    # AI 판별 결과
    ai_verdict: Mapped[str] = mapped_column(String(16), default="정탐")
    ai_confidence: Mapped[int] = mapped_column(Integer, default=0)
    ai_attack_type: Mapped[str] = mapped_column(String(64), default="")
    ai_reasoning: Mapped[str] = mapped_column(Text, default="")
    dup_count: Mapped[int] = mapped_column(Integer, default=1)  # 중복제거로 합쳐진 건수
    # 티켓팅
    ticket_no: Mapped[str] = mapped_column(String(32), default="", server_default=text("''"), index=True)
    priority: Mapped[str] = mapped_column(String(4), default="P3", server_default=text("'P3'"))
    due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)   # SLA 기한
    tags: Mapped[str] = mapped_column(String(255), default="", server_default=text("''"))      # 콤마 구분
    mitre: Mapped[str] = mapped_column(String(128), default="", server_default=text("''"))     # MITRE 기법 ID 콤마 구분
    origin: Mapped[str] = mapped_column(String(16), default="분석플랫폼", server_default=text("'분석플랫폼'"))  # 분석플랫폼 | 수동
    # 종결 정보
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolution_code: Mapped[str] = mapped_column(String(16), default="", server_default=text("''"))
    root_cause: Mapped[str] = mapped_column(Text, default="", server_default=text("''"))
    # 인간 검토(소통플랫폼 단계)
    status: Mapped[str] = mapped_column(String(16), default="미접수", index=True)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    assignee: Mapped["User | None"] = relationship()
    comments: Mapped[list["EventComment"]] = relationship(
        back_populates="event", cascade="all, delete-orphan", order_by="EventComment.created_at"
    )
    history: Mapped[list["EventHistory"]] = relationship(
        back_populates="event", cascade="all, delete-orphan", order_by="EventHistory.created_at"
    )
    attachments: Mapped[list["EventAttachment"]] = relationship(
        back_populates="event", cascade="all, delete-orphan", order_by="EventAttachment.created_at"
    )
    tasks: Mapped[list["EventTask"]] = relationship(
        back_populates="event", cascade="all, delete-orphan", order_by="EventTask.id"
    )


class EventComment(Base):
    __tablename__ = "event_comments"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    event: Mapped["Event"] = relationship(back_populates="comments")
    user: Mapped["User"] = relationship()


class EventHistory(Base):
    """이벤트 상태 변경/승인 이력 (감사 추적)."""
    __tablename__ = "event_history"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(64))         # 예: 상태변경, 배정
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    event: Mapped["Event"] = relationship(back_populates="history")
    user: Mapped["User | None"] = relationship()


class EventAttachment(Base):
    """티켓 첨부(증적 파일/스크린샷)."""
    __tablename__ = "event_attachments"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    url: Mapped[str] = mapped_column(String(512))
    name: Mapped[str] = mapped_column(String(255), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    uploaded_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    event: Mapped["Event"] = relationship(back_populates="attachments")
    uploaded_by: Mapped["User | None"] = relationship()


class EventTask(Base):
    """티켓 대응 작업/체크리스트 항목."""
    __tablename__ = "event_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"))
    title: Mapped[str] = mapped_column(String(255))
    done: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    event: Mapped["Event"] = relationship(back_populates="tasks")


class Channel(Base):
    __tablename__ = "channels"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    messages: Mapped[list["ChatMessage"]] = relationship(
        back_populates="channel", cascade="all, delete-orphan", order_by="ChatMessage.created_at"
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    channel_id: Mapped[int] = mapped_column(ForeignKey("channels.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    body: Mapped[str] = mapped_column(Text)
    event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"), nullable=True)  # 이벤트 카드 공유
    image_url: Mapped[str | None] = mapped_column(String(512), nullable=True)  # 첨부 이미지
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    channel: Mapped["Channel"] = relationship(back_populates="messages")
    user: Mapped["User"] = relationship()
    event: Mapped["Event | None"] = relationship()


class DirectMessage(Base):
    """1:1 다이렉트 메시지."""
    __tablename__ = "direct_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    body: Mapped[str] = mapped_column(Text)
    image_url: Mapped[str | None] = mapped_column(String(512), nullable=True)  # 첨부 이미지
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    sender: Mapped["User"] = relationship(foreign_keys=[sender_id])
    recipient: Mapped["User"] = relationship(foreign_keys=[recipient_id])


class IOC(Base):
    """침해지표(Indicator of Compromise) — 확정된 공격에서 추출한 차단/관찰 대상."""
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(primary_key=True)
    ioc_type: Mapped[str] = mapped_column(String(16), index=True)   # IP/도메인/URL/해시/이메일
    value: Mapped[str] = mapped_column(String(512), index=True)
    severity: Mapped[str] = mapped_column(String(8), default="2")
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    status: Mapped[str] = mapped_column(String(16), default="활성", index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    source_event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"), nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    first_seen: Mapped[str] = mapped_column(String(40), default="")
    last_seen: Mapped[str] = mapped_column(String(40), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)

    source_event: Mapped["Event | None"] = relationship()
    created_by: Mapped["User | None"] = relationship()


class Mail(Base):
    __tablename__ = "mails"

    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    # 인앱 수신자(플랫폼 사용자) — 외부 이메일 발송 시 NULL
    recipient_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    # 외부(사내 타 부서) 이메일 발송 시 사용
    recipient_email: Mapped[str] = mapped_column(String(255), default="", server_default=text("''"))
    recipient_name: Mapped[str] = mapped_column(String(64), default="", server_default=text("''"))
    recipient_dept: Mapped[str] = mapped_column(String(64), default="", server_default=text("''"))
    channel: Mapped[str] = mapped_column(String(16), default="inapp", server_default=text("'inapp'"))  # inapp | email
    subject: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    # 사용자별 삭제(소프트) — 받은/보낸 쪽이 각자 자기 편지함에서만 숨김
    del_sender: Mapped[bool] = mapped_column(Boolean, default=False)
    del_recipient: Mapped[bool] = mapped_column(Boolean, default=False)
    related_event_id: Mapped[int | None] = mapped_column(ForeignKey("events.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)

    sender: Mapped["User"] = relationship(foreign_keys=[sender_id])
    recipient: Mapped["User | None"] = relationship(foreign_keys=[recipient_id])
    related_event: Mapped["Event | None"] = relationship()


class Contact(Base):
    """사내 부서 연락처 (주소록) — 외부 이메일 발송 대상."""
    __tablename__ = "contacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    email: Mapped[str] = mapped_column(String(255), index=True)
    dept: Mapped[str] = mapped_column(String(64), default="")
    note: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
