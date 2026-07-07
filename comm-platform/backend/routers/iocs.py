"""IOC(침해지표) 관리 — 등록/조회/상태변경/삭제 + 이벤트에서 자동 추출."""
from urllib.parse import unquote_plus

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db import get_db
from models import IOC, IOC_STATUSES, IOC_TYPES, Event
from schemas import IOCIn, IOCOut, IOCUpdate

router = APIRouter(prefix="/api/iocs", tags=["iocs"])


def _upsert(db: Session, data: dict) -> IOC:
    """(타입, 값) 동일 IOC는 last_seen/신뢰도만 갱신, 없으면 신규 생성."""
    existing = db.scalar(
        select(IOC).where(IOC.ioc_type == data["ioc_type"], IOC.value == data["value"])
    )
    if existing:
        if data.get("last_seen"):
            existing.last_seen = data["last_seen"]
        existing.confidence = max(existing.confidence, data.get("confidence", 0))
        return existing
    ioc = IOC(**data)
    db.add(ioc)
    return ioc


@router.post("", response_model=IOCOut)
def create_ioc(req: IOCIn, db: Session = Depends(get_db)) -> IOC:
    if req.ioc_type not in IOC_TYPES:
        raise HTTPException(status_code=400, detail=f"유형은 {IOC_TYPES} 중 하나여야 합니다.")
    if not req.value.strip():
        raise HTTPException(status_code=400, detail="IOC 값이 비어 있습니다.")
    ioc = _upsert(db, req.model_dump())
    db.commit()
    db.refresh(ioc)
    return ioc


def _ioc_day(ioc: IOC) -> str:
    """IOC 날짜(YYYY-MM-DD) — 최초탐지 우선, 없으면 등록시각."""
    if ioc.first_seen and len(ioc.first_seen) >= 10:
        return ioc.first_seen[:10]
    return ioc.created_at.isoformat()[:10] if ioc.created_at else ""


@router.get("", response_model=list[IOCOut])
def list_iocs(
    ioc_type: str | None = Query(None),
    status: str | None = Query(None),
    q: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
    db: Session = Depends(get_db),
) -> list[IOC]:
    stmt = select(IOC).order_by(IOC.updated_at.desc())
    if ioc_type:
        stmt = stmt.where(IOC.ioc_type == ioc_type)
    if status:
        stmt = stmt.where(IOC.status == status)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(IOC.value.like(like) | IOC.description.like(like))
    rows = list(db.scalars(stmt))
    if date_from or date_to:
        out = []
        for ioc in rows:
            day = _ioc_day(ioc)
            if date_from and day < date_from:
                continue
            if date_to and day > date_to:
                continue
            out.append(ioc)
        return out
    return rows


@router.get("/stats")
def ioc_stats(db: Session = Depends(get_db)) -> dict:
    by_type = {t: 0 for t in IOC_TYPES}
    by_status = {s: 0 for s in IOC_STATUSES}
    for ioc in db.scalars(select(IOC)):
        by_type[ioc.ioc_type] = by_type.get(ioc.ioc_type, 0) + 1
        by_status[ioc.status] = by_status.get(ioc.status, 0) + 1
    total = sum(by_type.values())
    return {"total": total, "by_type": by_type, "by_status": by_status}


@router.patch("/{ioc_id}", response_model=IOCOut)
def update_ioc(ioc_id: int, req: IOCUpdate, db: Session = Depends(get_db)) -> IOC:
    ioc = db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC를 찾을 수 없습니다.")
    if req.status is not None:
        if req.status not in IOC_STATUSES:
            raise HTTPException(status_code=400, detail=f"상태는 {IOC_STATUSES} 중 하나여야 합니다.")
        ioc.status = req.status
    if req.severity is not None:
        ioc.severity = req.severity
    if req.confidence is not None:
        ioc.confidence = req.confidence
    if req.description is not None:
        ioc.description = req.description
    db.commit()
    db.refresh(ioc)
    return ioc


@router.delete("/{ioc_id}")
def delete_ioc(ioc_id: int, db: Session = Depends(get_db)) -> dict:
    ioc = db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC를 찾을 수 없습니다.")
    db.delete(ioc)
    db.commit()
    return {"deleted": True}


@router.post("/extract/{event_id}", response_model=list[IOCOut])
def extract_from_event(
    event_id: int, user_id: int | None = Query(None), db: Session = Depends(get_db)
) -> list[IOC]:
    """이벤트에서 IOC를 자동 추출 — 출발지 IP + 공격 URI."""
    ev = db.get(Event, event_id)
    if not ev:
        raise HTTPException(status_code=404, detail="이벤트를 찾을 수 없습니다.")

    created: list[IOC] = []
    base = dict(severity=ev.severity, confidence=ev.ai_confidence or 50,
                source_event_id=ev.id, created_by_id=user_id,
                first_seen=ev.detected_at, last_seen=ev.detected_at,
                description=f"이벤트 #{ev.id} ({ev.ai_attack_type or ev.signature})에서 자동 추출")

    if ev.src_ip:
        created.append(_upsert(db, {**base, "ioc_type": "IP", "value": ev.src_ip}))
    if ev.uri:
        # URI는 디코딩해 공격 페이로드가 드러나게 저장
        created.append(_upsert(db, {**base, "ioc_type": "URL", "value": unquote_plus(ev.uri)}))

    db.commit()
    for c in created:
        db.refresh(c)
    return created
