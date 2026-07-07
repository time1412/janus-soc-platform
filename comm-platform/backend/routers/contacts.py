"""사내 부서 연락처(주소록) — 외부 이메일 발송 대상 관리."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from db import get_db
from models import DEPARTMENTS, Contact
from schemas import ContactIn, ContactOut

router = APIRouter(prefix="/api", tags=["contacts"])


@router.get("/departments")
def list_departments() -> dict:
    return {"departments": DEPARTMENTS}


@router.get("/contacts", response_model=list[ContactOut])
def list_contacts(dept: str | None = Query(None), q: str | None = Query(None),
                  db: Session = Depends(get_db)) -> list[Contact]:
    stmt = select(Contact).order_by(Contact.dept, Contact.name)
    if dept:
        stmt = stmt.where(Contact.dept == dept)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(Contact.name.like(like) | Contact.email.like(like))
    return list(db.scalars(stmt))


@router.post("/contacts", response_model=ContactOut)
def add_contact(req: ContactIn, db: Session = Depends(get_db)) -> Contact:
    if not req.name.strip() or not req.email.strip():
        raise HTTPException(status_code=400, detail="이름과 이메일을 입력하세요.")
    c = Contact(name=req.name.strip(), email=req.email.strip(),
                dept=req.dept.strip(), note=req.note.strip())
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


@router.delete("/contacts/{contact_id}")
def delete_contact(contact_id: int, db: Session = Depends(get_db)) -> dict:
    c = db.get(Contact, contact_id)
    if not c:
        raise HTTPException(status_code=404, detail="연락처를 찾을 수 없습니다.")
    db.delete(c)
    db.commit()
    return {"deleted": True}
