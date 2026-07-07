"""소통플랫폼 — FastAPI 애플리케이션.

보안관제팀 ↔ 정보보호팀이 분석플랫폼에서 정탐 판정된 이벤트를
함께 검토/승인하고, 채팅·메일로 소통한다.
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

import config
from db import init_db
from realtime import manager
from routers import chat, contacts, dm, events, iocs, ledger, mail, mitre, upload, users
from seed import seed

app = FastAPI(title="내부 소통플랫폼", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()
    seed()


app.include_router(users.router)
app.include_router(events.router)
app.include_router(chat.router)
app.include_router(mail.router)
app.include_router(iocs.router)
app.include_router(ledger.router)
app.include_router(dm.router)
app.include_router(contacts.router)
app.include_router(upload.router)
app.include_router(mitre.router)

# 업로드 이미지 정적 서빙 (SPA 폴백보다 먼저 등록)
app.mount("/uploads", StaticFiles(directory=str(config.UPLOAD_DIR)), name="uploads")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "service": "내부 소통플랫폼"}


@app.get("/api/presence")
def presence() -> dict:
    return {"online": manager.online_ids()}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    """실시간 알림 채널 — 채팅/신규이벤트/신규메일/접속현황을 push 받는다."""
    raw = ws.query_params.get("user_id")
    user_id = int(raw) if raw and raw.isdigit() else None
    await manager.connect(ws, user_id)
    await manager.broadcast_presence()
    try:
        while True:
            await ws.receive_text()  # 클라이언트 ping 수신(연결 유지용)
    except WebSocketDisconnect:
        await manager.disconnect(ws)
        await manager.broadcast_presence()
    except Exception:
        await manager.disconnect(ws)
        await manager.broadcast_presence()


# ── 프론트엔드 정적 서빙 (React 빌드) ──
_FRONTEND_BUILD = config.BASE_DIR / "frontend" / "dist"
if _FRONTEND_BUILD.exists():
    app.mount("/assets", StaticFiles(directory=str(_FRONTEND_BUILD / "assets")), name="assets")

    @app.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
    def serve_spa(full_path: str) -> HTMLResponse:
        # index.html은 항상 최신 빌드를 받도록 캐시 금지(해시된 /assets는 그대로 캐시).
        # → 프로세스/버튼이 바뀌어도 브라우저가 옛 화면을 캐시해 보여주는 문제 방지.
        return HTMLResponse(
            (_FRONTEND_BUILD / "index.html").read_text(encoding="utf-8"),
            headers={"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"},
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=config.APP_HOST, port=config.APP_PORT, reload=True)
