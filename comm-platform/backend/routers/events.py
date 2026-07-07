"""정탐 이벤트 수신 + 관리 (인간 검토/승인) + 티켓팅."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from sqlalchemy import select
from sqlalchemy.orm import Session

from db import get_db
from models import (
    EVENT_STATUSES, PRIORITIES, TERMINAL_STATUSES, Event, EventAttachment,
    EventComment, EventHistory, EventTask, User, default_meta_for,
    mitre_ids, priority_from_severity,
)
from realtime import manager
from notify_service import notify_stage
from schemas import (
    AssignUpdate, AttachmentIn, CommentIn, CommentOut, EventDetail, EventOut,
    IngestBatch, IngestEvent, ManualTicketIn, MetaUpdate, PriorityUpdate,
    StatusUpdate, TaskIn, TaskToggle,
)
from ticketing import due_from, make_ticket_no

router = APIRouter(prefix="/api/events", tags=["events"])


def _finalize_ticket(db: Session, ev: Event, priority: str) -> None:
    """flush 후 ticket_no/우선순위/SLA 기한을 채운다."""
    ev.priority = priority
    ev.ticket_no = make_ticket_no(ev.created_at, ev.id)
    ev.due_at = due_from(ev.created_at, priority)


def _ingest_one(db: Session, e: IngestEvent) -> Event:
    # 태그는 공격 유형 기반 자동 생성. MITRE는 상관룰 큐레이션값 우선, 없으면 키워드 추론 폴백.
    d_tags, d_mitre = default_meta_for(e.ai_attack_type or e.signature)
    final_mitre = mitre_ids(e.mitre) or d_mitre
    ev = Event(
        signature=e.signature, src_ip=e.src_ip, dest_ip=e.dest_ip,
        src_port=e.src_port, dest_port=e.dest_port, asset=e.asset, uri=e.uri,
        payload=e.payload,
        severity=e.severity, source=e.source, detected_at=e.detected_at,
        ai_verdict=e.ai_verdict, ai_confidence=e.ai_confidence,
        ai_attack_type=e.ai_attack_type, ai_reasoning=e.ai_reasoning,
        dup_count=e.dup_count, status="미접수", origin="분석플랫폼",
        tags=d_tags, mitre=final_mitre,
    )
    db.add(ev)
    db.flush()
    _finalize_ticket(db, ev, priority_from_severity(e.severity))
    db.add(EventHistory(event_id=ev.id, user_id=None, action="수신",
                        detail=f"분석플랫폼에서 정탐 수신 (AI {e.ai_confidence}%) · {ev.ticket_no}"))
    return ev


@router.post("/ingest")
async def ingest(batch: IngestBatch, db: Session = Depends(get_db)) -> dict:
    """분석플랫폼에서 정탐 판정된 이벤트를 수신해 적재한다."""
    created = [_ingest_one(db, e) for e in batch.events]
    db.commit()
    for ev in created:
        await manager.broadcast({
            "type": "new_event",
            "event": {"id": ev.id, "signature": ev.signature,
                      "src_ip": ev.src_ip, "severity": ev.severity,
                      "ai_attack_type": ev.ai_attack_type},
        })
        # 발송(블로킹 I/O)은 스레드풀로 — 이벤트 루프 비차단. 폭주 가드가 상한 적용.
        await run_in_threadpool(notify_stage, db, ev, "미접수", None)
    return {"ingested": len(created), "ids": [e.id for e in created]}


@router.post("/ticket", response_model=EventDetail)
async def create_ticket(req: ManualTicketIn, db: Session = Depends(get_db)) -> Event:
    """분석가가 직접 티켓(이벤트)을 생성한다."""
    if not req.signature.strip():
        raise HTTPException(status_code=400, detail="제목(유형)을 입력하세요.")
    priority = req.priority if req.priority in PRIORITIES else priority_from_severity(req.severity)
    # 태그·MITRE 미입력 시 공격 유형 기반 기본값 자동 생성
    d_tags, d_mitre = default_meta_for(req.attack_type or req.signature)
    ev = Event(
        signature=req.signature.strip(), src_ip=req.src_ip, dest_ip=req.dest_ip,
        src_port=req.src_port, dest_port=req.dest_port, uri=req.uri,
        severity=req.severity, source="manual", origin="수동",
        ai_verdict="수동", ai_confidence=0, ai_attack_type=req.attack_type,
        ai_reasoning=req.description, dup_count=1, status="미접수",
        tags=req.tags.strip() or d_tags, mitre=req.mitre.strip() or d_mitre,
    )
    db.add(ev)
    db.flush()
    _finalize_ticket(db, ev, priority)
    creator = db.get(User, req.user_id)
    db.add(EventHistory(event_id=ev.id, user_id=req.user_id, action="티켓생성",
                        detail=f"수동 생성 · {ev.ticket_no} ({creator.display_name if creator else '?'})"))
    db.commit()
    db.refresh(ev)
    await manager.broadcast({
        "type": "new_event",
        "event": {"id": ev.id, "signature": ev.signature, "src_ip": ev.src_ip,
                  "severity": ev.severity, "ai_attack_type": ev.ai_attack_type},
    })
    await run_in_threadpool(notify_stage, db, ev, "미접수", req.user_id)   # 수동 신규 티켓 알림
    return ev


@router.get("", response_model=list[EventOut])
def list_events(
    status: str | None = Query(None),
    assignee_id: int | None = Query(None),
    db: Session = Depends(get_db),
) -> list[Event]:
    stmt = select(Event).order_by(Event.created_at.desc())
    if status:
        stmt = stmt.where(Event.status == status)
    if assignee_id is not None:
        stmt = stmt.where(Event.assignee_id == assignee_id)
    return list(db.scalars(stmt))


@router.get("/stats")
def stats(db: Session = Depends(get_db)) -> dict:
    """상태별 건수 요약 (대시보드용)."""
    counts = {s: 0 for s in EVENT_STATUSES}
    for ev in db.scalars(select(Event)):
        counts[ev.status] = counts.get(ev.status, 0) + 1
    return {"total": sum(counts.values()), "by_status": counts}


@router.get("/metrics")
def metrics(db: Session = Depends(get_db)) -> dict:
    """SOC 티켓 지표 — MTTR · SLA 준수율 · 우선순위 분포 · 분석가별."""
    evs = list(db.scalars(select(Event)))
    now = datetime.utcnow()
    by_priority = {p: 0 for p in PRIORITIES}
    by_assignee: dict[str, int] = {}
    durations: list[float] = []
    sla_total = sla_ok = open_overdue = closed = 0
    for ev in evs:
        by_priority[ev.priority] = by_priority.get(ev.priority, 0) + 1
        if ev.assignee_id:
            name = ev.assignee.display_name if ev.assignee else str(ev.assignee_id)
            by_assignee[name] = by_assignee.get(name, 0) + 1
        if ev.resolved_at:
            closed += 1
            durations.append((ev.resolved_at - ev.created_at).total_seconds() / 3600)
            if ev.due_at:
                sla_total += 1
                if ev.resolved_at <= ev.due_at:
                    sla_ok += 1
        elif ev.due_at and now > ev.due_at and ev.status not in TERMINAL_STATUSES:
            open_overdue += 1
    top = sorted(by_assignee.items(), key=lambda x: -x[1])[:6]
    return {
        "total": len(evs), "open": len(evs) - closed, "closed": closed,
        "mttr_hours": round(sum(durations) / len(durations), 1) if durations else 0,
        "sla_rate": round(sla_ok / sla_total * 100) if sla_total else 100,
        "open_overdue": open_overdue,
        "by_priority": by_priority,
        "by_assignee": [{"name": n, "count": c} for n, c in top],
    }


@router.get("/progress")
def progress(scope: str = Query("open"), db: Session = Depends(get_db)) -> dict:
    """티켓 진척도 — 처리 단계 + 체크리스트 완료율 + SLA 잔여를 티켓별로 집계.

    scope=open(기본): 미종결 티켓만 / scope=all: 종결 포함.
    """
    now = datetime.utcnow()
    # 처리 단계별 진행률(워크플로 위치)
    stage_pct = {"미접수": 10, "접수": 25, "검토": 45, "대응": 65, "승인대기": 85,
                 "오탐요청": 40, "무시종결요청": 40, "종결": 100, "오탐종결": 100, "무시종결": 100}
    prio_rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

    tickets: list[dict] = []
    summary = {"진행중": 0, "정상": 0, "임박": 0, "초과": 0}
    for ev in db.scalars(select(Event).order_by(Event.created_at.desc())):
        is_open = ev.status not in TERMINAL_STATUSES
        if scope == "open" and not is_open:
            continue

        t_total = len(ev.tasks)
        t_done = sum(1 for t in ev.tasks if t.done)
        t_pct = round(t_done / t_total * 100) if t_total else 0

        sla = None
        if ev.due_at:
            total = (ev.due_at - ev.created_at).total_seconds()
            elapsed = (now - ev.created_at).total_seconds()
            pct = round(min(max(elapsed / total, 0), 1) * 100) if total > 0 else 100
            remaining_h = round((ev.due_at - now).total_seconds() / 3600, 1)
            overdue = is_open and now > ev.due_at
            if not is_open:
                state = "종료"
            elif overdue:
                state = "초과"
            elif remaining_h < 1:
                state = "임박"
            else:
                state = "정상"
            sla = {"pct": pct, "remaining_hours": remaining_h, "overdue": overdue, "state": state}
            if is_open and state in summary:
                summary[state] += 1
        if is_open:
            summary["진행중"] += 1

        tickets.append({
            "id": ev.id, "ticket_no": ev.ticket_no, "signature": ev.signature,
            "src_ip": ev.src_ip, "severity": ev.severity, "priority": ev.priority,
            "attack_type": ev.ai_attack_type, "status": ev.status, "is_open": is_open,
            "stage_pct": stage_pct.get(ev.status, 0),
            "assignee": ev.assignee.display_name if ev.assignee else None,
            "assignee_team": ev.assignee.team if ev.assignee else None,
            "tasks": {"done": t_done, "total": t_total, "pct": t_pct},
            "sla": sla,
        })

    # 정렬: SLA 초과 → 임박 → 우선순위 높은 순 → (이미 최신순)
    def urgency(t: dict) -> tuple:
        s = t.get("sla") or {}
        rank = 0 if s.get("overdue") else (1 if s.get("state") == "임박" else 2)
        return (0 if t["is_open"] else 1, rank, prio_rank.get(t["priority"], 9))
    tickets.sort(key=urgency)

    return {"tickets": tickets, "summary": summary, "count": len(tickets)}


@router.get("/{event_id}", response_model=EventDetail)
def get_event(event_id: int, db: Session = Depends(get_db)) -> Event:
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="이벤트를 찾을 수 없습니다.")
    return ev


@router.post("/{event_id}/status", response_model=EventDetail)
async def update_status(event_id: int, req: StatusUpdate, db: Session = Depends(get_db)) -> Event:
    if req.status not in EVENT_STATUSES:
        raise HTTPException(status_code=400, detail=f"상태는 {EVENT_STATUSES} 중 하나여야 합니다.")
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="이벤트를 찾을 수 없습니다.")
    prev = ev.status
    ev.status = req.status
    detail = f"{prev} → {req.status}"
    if req.status in TERMINAL_STATUSES:
        ev.resolved_at = ev.resolved_at or datetime.now(timezone.utc)
        if req.resolution_code:
            ev.resolution_code = req.resolution_code
            detail += f" · 종결[{req.resolution_code}]"
        if req.root_cause:
            ev.root_cause = req.root_cause
    else:
        ev.resolved_at = None  # 재오픈 시 종결 정보 전체 해제
        ev.resolution_code = ""
        ev.root_cause = ""
    if req.note:
        detail += f" · {req.note}"
    db.add(EventHistory(event_id=ev.id, user_id=req.user_id, action="상태변경", detail=detail))
    db.commit()
    db.refresh(ev)
    # 인앱 실시간 알림(WebSocket)
    if req.status in ("검토", "대응", "승인대기", "오탐요청", "무시종결요청"):
        await manager.broadcast({
            "type": "ticket_status",
            "event": {"id": ev.id, "ticket_no": ev.ticket_no, "signature": ev.signature,
                      "status": ev.status, "assignee_team": ev.assignee.team if ev.assignee else None},
        })
    # 외부 알림(카톡 + 이메일) + 기록 — 단계 전이마다 (반려 사유 note 포함). 스레드풀로 비차단.
    await run_in_threadpool(notify_stage, db, ev, req.status, req.user_id, req.note)
    db.refresh(ev)
    return ev


@router.post("/{event_id}/assign", response_model=EventDetail)
def assign(event_id: int, req: AssignUpdate, db: Session = Depends(get_db)) -> Event:
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="이벤트를 찾을 수 없습니다.")
    ev.assignee_id = req.assignee_id
    target = db.get(User, req.assignee_id) if req.assignee_id else None
    detail = f"담당자: {target.display_name if target else '(해제)'}"
    db.add(EventHistory(event_id=ev.id, user_id=req.user_id, action="배정", detail=detail))
    db.commit()
    db.refresh(ev)
    return ev


@router.post("/{event_id}/comments", response_model=CommentOut)
def add_comment(event_id: int, req: CommentIn, db: Session = Depends(get_db)) -> EventComment:
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="이벤트를 찾을 수 없습니다.")
    c = EventComment(event_id=event_id, user_id=req.user_id, body=req.body)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@router.post("/{event_id}/priority", response_model=EventDetail)
def update_priority(event_id: int, req: PriorityUpdate, db: Session = Depends(get_db)) -> Event:
    if req.priority not in PRIORITIES:
        raise HTTPException(status_code=400, detail=f"우선순위는 {PRIORITIES} 중 하나여야 합니다.")
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="이벤트를 찾을 수 없습니다.")
    prev = ev.priority
    ev.priority = req.priority
    ev.due_at = due_from(ev.created_at, req.priority)  # SLA 기한 재계산
    db.add(EventHistory(event_id=ev.id, user_id=req.user_id, action="우선순위",
                        detail=f"{prev} → {req.priority} (SLA 재설정)"))
    db.commit()
    db.refresh(ev)
    return ev


@router.patch("/{event_id}/meta", response_model=EventDetail)
def update_meta(event_id: int, req: MetaUpdate, db: Session = Depends(get_db)) -> Event:
    """태그 / MITRE ATT&CK 수정."""
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="이벤트를 찾을 수 없습니다.")
    changes = []
    if req.tags is not None and req.tags != ev.tags:
        ev.tags = req.tags
        changes.append("태그")
    if req.mitre is not None and req.mitre != ev.mitre:
        ev.mitre = req.mitre
        changes.append("MITRE")
    if changes:
        db.add(EventHistory(event_id=ev.id, user_id=req.user_id, action="분류수정",
                            detail=", ".join(changes) + " 변경"))
    db.commit()
    db.refresh(ev)
    return ev


@router.post("/{event_id}/attachments", response_model=EventDetail)
def add_attachment(event_id: int, req: AttachmentIn, db: Session = Depends(get_db)) -> Event:
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="이벤트를 찾을 수 없습니다.")
    db.add(EventAttachment(event_id=event_id, url=req.url, name=req.name,
                           size=req.size, uploaded_by_id=req.user_id))
    db.add(EventHistory(event_id=ev.id, user_id=req.user_id, action="첨부",
                        detail=f"파일 첨부: {req.name or req.url}"))
    db.commit()
    db.refresh(ev)
    return ev


@router.delete("/{event_id}/attachments/{att_id}")
def delete_attachment(event_id: int, att_id: int, db: Session = Depends(get_db)) -> dict:
    att = db.get(EventAttachment, att_id)
    if not att or att.event_id != event_id:
        raise HTTPException(status_code=404, detail="첨부를 찾을 수 없습니다.")
    db.delete(att)
    db.commit()
    return {"deleted": True}


# ── 대응 작업/체크리스트 ──
@router.post("/{event_id}/tasks", response_model=EventDetail)
def add_task(event_id: int, req: TaskIn, db: Session = Depends(get_db)) -> Event:
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="이벤트를 찾을 수 없습니다.")
    if not req.title.strip():
        raise HTTPException(status_code=400, detail="작업 내용을 입력하세요.")
    db.add(EventTask(event_id=event_id, title=req.title.strip()))
    db.commit()
    db.refresh(ev)
    return ev


@router.patch("/{event_id}/tasks/{task_id}", response_model=EventDetail)
def toggle_task(event_id: int, task_id: int, req: TaskToggle, db: Session = Depends(get_db)) -> Event:
    t = db.get(EventTask, task_id)
    if not t or t.event_id != event_id:
        raise HTTPException(status_code=404, detail="작업을 찾을 수 없습니다.")
    t.done = req.done
    db.commit()
    ev = db.get(Event, event_id)
    db.refresh(ev)
    return ev


@router.delete("/{event_id}/tasks/{task_id}")
def delete_task(event_id: int, task_id: int, db: Session = Depends(get_db)) -> dict:
    t = db.get(EventTask, task_id)
    if not t or t.event_id != event_id:
        raise HTTPException(status_code=404, detail="작업을 찾을 수 없습니다.")
    db.delete(t)
    db.commit()
    return {"deleted": True}
