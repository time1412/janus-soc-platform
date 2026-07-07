"""WebSocket 실시간 브로드캐스트 + 접속 현황(presence) 관리자.

채팅 메시지/신규 이벤트/신규 메일/접속현황을 연결된 모든 클라이언트에
JSON으로 push 한다. 클라이언트는 type으로 분기 처리한다.
"""
import asyncio
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self) -> None:
        self._conns: dict[WebSocket, int | None] = {}   # ws -> user_id
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, user_id: int | None) -> None:
        """새 연결 수락. 같은 user_id의 기존 세션이 있으면 강제 로그아웃시킨다(중복 로그인 방지)."""
        await ws.accept()
        async with self._lock:
            dups = (
                [w for w, uid in self._conns.items() if uid == user_id]
                if user_id is not None else []
            )
            self._conns[ws] = user_id
        for w in dups:
            try:
                await w.send_json({
                    "type": "force_logout",
                    "reason": "다른 위치에서 로그인하여 현재 세션이 종료되었습니다.",
                })
            except Exception:
                pass
            try:
                await w.close(code=4001)
            except Exception:
                pass
            async with self._lock:
                self._conns.pop(w, None)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._conns.pop(ws, None)

    def online_ids(self) -> list[int]:
        return sorted({uid for uid in self._conns.values() if uid})

    async def broadcast(self, message: dict[str, Any]) -> None:
        """모든 연결에 메시지 전송. 끊긴 연결은 정리한다."""
        async with self._lock:
            targets = list(self._conns.keys())
        dead = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._conns.pop(ws, None)

    async def send_to_users(self, user_ids: set[int], message: dict[str, Any]) -> None:
        """지정한 사용자들의 소켓에만 전송 (DM 등 비공개 메시지용)."""
        ids = {u for u in user_ids if u is not None}
        async with self._lock:
            targets = [ws for ws, uid in self._conns.items() if uid in ids]
        dead = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._conns.pop(ws, None)

    async def broadcast_presence(self) -> None:
        await self.broadcast({"type": "presence", "online": self.online_ids()})


manager = ConnectionManager()
