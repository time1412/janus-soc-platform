# -*- coding: utf-8 -*-
"""티켓팅 내역 전체 초기화 — 이벤트(티켓) + 코멘트·이력·첨부·작업 삭제.

IOC(탐지이력 대장)는 보존하되, 삭제될 티켓을 가리키는 참조만 해제한다.
채팅/메일의 이벤트 카드 참조도 해제한다.
"""
from sqlalchemy import text

from db import engine

with engine.begin() as conn:
    n = conn.execute(text("SELECT COUNT(*) FROM events")).scalar() or 0
    # 외부 참조 해제(티켓 카드 공유·메일 연동·IOC 출처)
    conn.execute(text("UPDATE chat_messages SET event_id=NULL WHERE event_id IS NOT NULL"))
    conn.execute(text("UPDATE mails SET related_event_id=NULL WHERE related_event_id IS NOT NULL"))
    conn.execute(text("UPDATE iocs SET source_event_id=NULL WHERE source_event_id IS NOT NULL"))
    # 티켓 하위 레코드 → 티켓 본체 순으로 삭제
    for tbl in ["event_tasks", "event_attachments", "event_history", "event_comments", "events"]:
        conn.execute(text(f"DELETE FROM {tbl}"))
    remain = conn.execute(text("SELECT COUNT(*) FROM events")).scalar()

print(f"삭제된 티켓: {n}건 · 남은 티켓: {remain}건")
