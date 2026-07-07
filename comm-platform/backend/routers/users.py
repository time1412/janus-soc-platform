"""사용자 / 로그인 (데모 수준 인증)."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

import config
from db import get_db
from models import TEAMS, User
from schemas import LoginIn, SignupIn, UserOut

router = APIRouter(prefix="/api", tags=["users"])


@router.post("/login", response_model=UserOut)
def login(req: LoginIn, db: Session = Depends(get_db)) -> User:
    user = db.scalar(select(User).where(User.username == req.username))
    if not user or user.password != req.password:
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 올바르지 않습니다.")
    return user


@router.post("/signup", response_model=UserOut)
def signup(req: SignupIn, db: Session = Depends(get_db)) -> User:
    username = req.username.strip()
    if not username or not req.password or not req.display_name.strip():
        raise HTTPException(status_code=400, detail="아이디·비밀번호·이름을 모두 입력하세요.")
    if len(req.password) < 4:
        raise HTTPException(status_code=400, detail="비밀번호는 4자 이상이어야 합니다.")
    if req.team not in TEAMS:
        raise HTTPException(status_code=400, detail=f"소속은 {TEAMS} 중 하나여야 합니다.")
    if db.scalar(select(User).where(User.username == username)):
        raise HTTPException(status_code=409, detail="이미 사용 중인 아이디입니다.")
    # janus.com 사서함: <앞부분>@janus.com (앞부분 비우면 아이디 사용), 메일 비번=로그인 비번
    local = ((req.mail_local or username).strip().split("@")[0]) or username
    mail_addr = f"{local}@{config.MAIL_DOMAIN}"
    if db.scalar(select(User).where(User.mail_address == mail_addr)):
        raise HTTPException(status_code=409, detail=f"이미 사용 중인 메일 주소입니다: {mail_addr}")
    user = User(username=username, password=req.password,
                display_name=req.display_name.strip(), team=req.team,
                role=req.role.strip() or "분석가",
                email=mail_addr, phone=req.phone.strip(),
                notify_consent=bool(req.notify_consent),
                mail_address=mail_addr, mail_password=req.password)
    db.add(user)
    db.commit()
    db.refresh(user)
    # 게이트웨이에 사서함 자동 생성(설정 켜졌을 때만). 실패해도 가입은 유지(로그만).
    if config.MAIL_PROVISION_ENABLED:
        try:
            import mail_provision
            ok, info = mail_provision.create_mailbox(mail_addr, req.password)
            if not ok:
                print(f"[mail_provision] FAILED {mail_addr}: {info}")
        except Exception as exc:  # noqa: BLE001
            print(f"[mail_provision] EXC {mail_addr}: {exc}")
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.team, User.id)))
