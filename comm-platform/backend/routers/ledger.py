"""탐지이력 관리대장 — 모든 탐지 이벤트의 처리 내역을 정식 대장으로 + CSV 내보내기."""
import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from db import get_db
from models import Event, EventHistory, User

router = APIRouter(prefix="/api/ledger", tags=["ledger"])

SEV_LABEL = {"3": "고위험", "2": "주의", "1": "낮음"}
_KST = timezone(timedelta(hours=9))


def _kst_iso(dt: datetime | None) -> str:
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_KST).isoformat()


def _row_day(ev: Event) -> str:
    """이벤트의 날짜(YYYY-MM-DD, KST) — 탐지시각 우선, 없으면 수신시각."""
    if ev.detected_at and len(ev.detected_at) >= 10:
        return ev.detected_at[:10]
    return _kst_iso(ev.created_at)[:10]


def _ledger_rows(
    db: Session, status: str | None, attack_type: str | None, q: str | None,
    src_ip: str | None = None, date_from: str | None = None, date_to: str | None = None,
) -> list[dict]:
    stmt = select(Event).order_by(Event.created_at.desc())
    if status:
        stmt = stmt.where(Event.status == status)
    if attack_type:
        stmt = stmt.where(Event.ai_attack_type == attack_type)
    events = list(db.scalars(stmt))

    rows = []
    for ev in events:
        if q and q.lower() not in (ev.signature + ev.src_ip + ev.dest_ip + ev.uri).lower():
            continue
        if src_ip and src_ip not in (ev.src_ip or ""):
            continue
        if date_from or date_to:
            day = _row_day(ev)
            if date_from and day < date_from:
                continue
            if date_to and day > date_to:
                continue
        # 최종 결정(가장 최근 상태변경) 추출
        last = db.scalar(
            select(EventHistory)
            .where(EventHistory.event_id == ev.id, EventHistory.action == "상태변경")
            .order_by(EventHistory.created_at.desc())
            .limit(1)
        )
        decided_by = None
        decided_at = None
        if last:
            decided_at = _kst_iso(last.created_at)
            if last.user_id:
                u = db.get(User, last.user_id)
                decided_by = u.display_name if u else None
        rows.append({
            "id": ev.id,
            "ticket_no": ev.ticket_no,
            "priority": ev.priority,
            "resolution_code": ev.resolution_code,
            "detected_at": ev.detected_at,
            "signature": ev.signature,
            "attack_type": ev.ai_attack_type,
            "src_ip": ev.src_ip,
            "dest_ip": ev.dest_ip,
            "severity": SEV_LABEL.get(ev.severity, ev.severity),
            "ai_verdict": ev.ai_verdict,
            "ai_confidence": ev.ai_confidence,
            "dup_count": ev.dup_count,
            "status": ev.status,
            "assignee": ev.assignee.display_name if ev.assignee else "",
            "decided_by": decided_by or "",
            "decided_at": decided_at or "",
            "created_at": _kst_iso(ev.created_at),
        })
    return rows


@router.get("")
def ledger(
    status: str | None = Query(None),
    attack_type: str | None = Query(None),
    q: str | None = Query(None),
    src_ip: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: Session = Depends(get_db),
) -> dict:
    rows = _ledger_rows(db, status, attack_type, q, src_ip, date_from, date_to)
    return {"count": len(rows), "rows": rows}


@router.get("/export")
def export_csv(
    status: str | None = Query(None),
    attack_type: str | None = Query(None),
    q: str | None = Query(None),
    src_ip: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: Session = Depends(get_db),
) -> StreamingResponse:
    rows = _ledger_rows(db, status, attack_type, q, src_ip, date_from, date_to)
    buf = io.StringIO()
    buf.write("﻿")  # Excel 한글 깨짐 방지 BOM
    writer = csv.writer(buf)
    writer.writerow([
        "티켓번호", "우선순위", "탐지일시", "시그니처", "공격유형", "출발지IP", "목적지IP",
        "위험도", "AI판정", "AI신뢰도", "반복횟수", "처리상태", "종결코드", "담당자", "결정자", "결정일시",
    ])
    for r in rows:
        writer.writerow([
            r["ticket_no"], r["priority"], r["detected_at"], r["signature"], r["attack_type"],
            r["src_ip"], r["dest_ip"], r["severity"], r["ai_verdict"], r["ai_confidence"],
            r["dup_count"], r["status"], r["resolution_code"], r["assignee"], r["decided_by"], r["decided_at"],
        ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="detection_ledger.csv"'},
    )
