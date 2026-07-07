"""초기 데이터 — 기본 채팅 채널만 생성 (계정/이벤트는 시드하지 않음).

사용자는 직접 회원가입한다. 채널은 공용 협업 공간이라 기본값을 제공한다.
"""
from sqlalchemy import select

from db import SessionLocal
from models import Channel, Contact, Event, priority_from_severity
from ticketing import due_from, make_ticket_no

_CHANNELS = [
    ("전체-공지", "전사 보안 공지 채널"),
    ("관제-정보보호", "보안관제팀 ↔ 정보보호팀 협업 채널"),
    ("긴급-침해대응", "고위험 이벤트 긴급 대응 채널"),
]

# 주소록 예시 (외부 부서 담당자) — 실제 운영 시 교체
_CONTACTS = [
    ("김개발", "dev-lead@company.local", "개발팀", "백엔드 리드"),
    ("이서버", "infra@company.local", "인프라팀", "서버/네트워크 담당"),
    ("박운영", "ops@company.local", "운영팀", "서비스 운영"),
    ("최디비", "dba@company.local", "DBA팀", "DB 관리자"),
]


def seed() -> None:
    db = SessionLocal()
    try:
        if db.scalar(select(Channel).limit(1)) is None:
            for name, desc in _CHANNELS:
                db.add(Channel(name=name, description=desc))
            db.commit()

        if db.scalar(select(Contact).limit(1)) is None:
            for name, email, dept, note in _CONTACTS:
                db.add(Contact(name=name, email=email, dept=dept, note=note))
            db.commit()

        # 기존 이벤트에 티켓번호/우선순위/SLA 백필
        changed = False
        for ev in db.scalars(select(Event).where((Event.ticket_no == "") | (Event.ticket_no.is_(None)))):
            ev.ticket_no = make_ticket_no(ev.created_at, ev.id)
            if not ev.priority or ev.priority not in ("P1", "P2", "P3", "P4"):
                ev.priority = priority_from_severity(ev.severity)
            if ev.due_at is None:
                ev.due_at = due_from(ev.created_at, ev.priority)
            changed = True
        if changed:
            db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    seed()
    print("seed 완료")
