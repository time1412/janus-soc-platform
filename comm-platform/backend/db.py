"""SQLite + SQLAlchemy 세션 관리."""
from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DB_PATH = Path(__file__).resolve().parent / "storage" / "comm.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 10},  # FastAPI 멀티스레드 + 락 대기
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _record) -> None:
    """다중 사용자 동시성/내구성 설정.

    WAL: 읽기와 쓰기가 서로 막지 않음(동시 접속에 유리).
    busy_timeout: 락 충돌 시 즉시 에러 대신 대기 → 'database is locked' 방지.
    synchronous=NORMAL: WAL과 함께 쓰는 권장값(성능/안정 균형).
    """
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA busy_timeout=10000")
    cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI 의존성 — 요청마다 세션 발급/정리."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """모든 테이블 생성 (이미 있으면 무시) + 간단 마이그레이션."""
    import models  # noqa: F401 — 모델 등록
    _pre_migrate()
    Base.metadata.create_all(bind=engine)
    _post_migrate()


def _cols(conn, table: str) -> set[str]:
    from sqlalchemy import text
    return {row[1] for row in conn.execute(text(f"PRAGMA table_info({table})"))}


def _has_table(conn, table: str) -> bool:
    from sqlalchemy import text
    r = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name=:n"), {"n": table})
    return r.first() is not None


def _pre_migrate() -> None:
    """구버전 mails 테이블(외부수신/채널 컬럼 없음)을 백업해 새 스키마로 재생성하도록 준비."""
    from sqlalchemy import text
    with engine.begin() as conn:
        if _has_table(conn, "mails") and "channel" not in _cols(conn, "mails"):
            conn.execute(text("ALTER TABLE mails RENAME TO mails_old"))


def _post_migrate() -> None:
    from sqlalchemy import text
    with engine.begin() as conn:
        chat_cols = _cols(conn, "chat_messages")
        if "event_id" not in chat_cols:
            conn.execute(text("ALTER TABLE chat_messages ADD COLUMN event_id INTEGER"))
        if "image_url" not in chat_cols:
            conn.execute(text("ALTER TABLE chat_messages ADD COLUMN image_url VARCHAR(512)"))

        if _has_table(conn, "direct_messages"):
            dm_cols = _cols(conn, "direct_messages")
            if "image_url" not in dm_cols:
                conn.execute(text("ALTER TABLE direct_messages ADD COLUMN image_url VARCHAR(512)"))

        # 티켓팅 컬럼
        ev_cols = _cols(conn, "events")
        _add = {
            "payload": "TEXT DEFAULT ''",
            "asset": "VARCHAR(128) DEFAULT ''",
            "src_port": "VARCHAR(8) DEFAULT ''",
            "dest_port": "VARCHAR(8) DEFAULT ''",
            "ticket_no": "VARCHAR(32) DEFAULT ''",
            "priority": "VARCHAR(4) DEFAULT 'P3'",
            "due_at": "DATETIME",
            "tags": "VARCHAR(255) DEFAULT ''",
            "mitre": "VARCHAR(128) DEFAULT ''",
            "origin": "VARCHAR(16) DEFAULT '분석플랫폼'",
            "resolved_at": "DATETIME",
            "resolution_code": "VARCHAR(16) DEFAULT ''",
            "root_cause": "TEXT DEFAULT ''",
        }
        for col, ddl in _add.items():
            if col not in ev_cols:
                conn.execute(text(f"ALTER TABLE events ADD COLUMN {col} {ddl}"))

        # 구버전 상태값 → 신버전 라이프사이클 상태로 일괄 변환
        from models import LEGACY_STATUS_MAP
        for old, new in LEGACY_STATUS_MAP.items():
            conn.execute(text("UPDATE events SET status=:new WHERE status=:old"),
                         {"new": new, "old": old})

        # 플레이북 기능 제거 — 잔존 테이블 정리
        conn.execute(text("DROP TABLE IF EXISTS playbooks"))

        # 사용자 알림 연락처(이메일·전화·수신동의) 컬럼 추가
        user_cols = _cols(conn, "users")
        for col, ddl in {"email": "VARCHAR(255) DEFAULT ''", "phone": "VARCHAR(32) DEFAULT ''",
                         "notify_consent": "BOOLEAN DEFAULT 0",
                         "mail_address": "VARCHAR(255) DEFAULT ''",
                         "mail_password": "VARCHAR(128) DEFAULT ''"}.items():
            if col not in user_cols:
                conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} {ddl}"))

        # 백업된 구 mails 데이터를 새 mails로 복원 (공통 컬럼 + 신규 컬럼은 기본값 명시)
        if _has_table(conn, "mails_old"):
            old, new = _cols(conn, "mails_old"), _cols(conn, "mails")
            shared = [c for c in old if c in new]
            new_defaults = {"recipient_email": "''", "recipient_name": "''",
                            "recipient_dept": "''", "channel": "'inapp'"}
            extra = [c for c in new_defaults if c in new and c not in shared]
            targets = ", ".join(shared + extra)
            exprs = ", ".join(shared + [new_defaults[c] for c in extra])
            conn.execute(text(f"INSERT INTO mails ({targets}) SELECT {exprs} FROM mails_old"))
            conn.execute(text("DROP TABLE mails_old"))
