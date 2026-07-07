"""검증: IOC 최초탐지/설명 저장+조회, 채팅 WS created_at에 KST(+09:00) 오프셋."""
import json
import threading
import time

import requests
from websockets.sync.client import connect

B = "http://localhost:8810"
WS = "ws://localhost:8810/ws"


def main() -> None:
    u = requests.post(f"{B}/api/signup", json={
        "username": "tester1", "password": "1234", "display_name": "테스터",
        "team": "보안관제팀"}).json()
    if not u.get("id"):
        u = requests.post(f"{B}/api/login", json={"username": "tester1", "password": "1234"}).json()

    # ── IOC: 최초탐지 + 설명 저장/조회 ──
    requests.post(f"{B}/api/iocs", json={
        "ioc_type": "도메인", "value": "manual-test.example.com",
        "severity": "3", "confidence": 85, "first_seen": "2026-06-01",
        "last_seen": "2026-06-01", "description": "수동 등록 C2 도메인 — 위협 인텔 근거",
        "created_by_id": u["id"]})
    got = [x for x in requests.get(f"{B}/api/iocs?q=manual-test").json() if x["value"] == "manual-test.example.com"][0]
    assert got["first_seen"][:10] == "2026-06-01", got["first_seen"]
    assert "C2 도메인" in got["description"], got["description"]
    print(f"✅ IOC 최초탐지 저장: {got['first_seen'][:10]}")
    print(f"✅ IOC 설명 저장/조회: \"{got['description']}\"")

    # ── 채팅 WS created_at 오프셋 ──
    ch = requests.get(f"{B}/api/chat/channels").json()[0]
    received = {}

    def listen():
        with connect(f"{WS}?user_id={u['id']}") as ws:
            try:
                while True:
                    d = json.loads(ws.recv(timeout=6))
                    if d.get("type") == "chat_message":
                        received["msg"] = d["message"]; break
            except Exception:
                pass

    t = threading.Thread(target=listen); t.start(); time.sleep(0.6)
    requests.post(f"{B}/api/chat/channels/{ch['id']}/messages",
                  json={"user_id": u["id"], "body": "시간 동기화 테스트"})
    t.join(timeout=7)

    ca = received.get("msg", {}).get("created_at", "")
    print(f"   WS created_at = {ca}")
    assert ca.endswith("+09:00"), f"오프셋 누락: {ca}"
    print("✅ 채팅 WS created_at 에 KST(+09:00) 오프셋 포함 (새로고침 없이 정상 시간)")

    print("\n🎉 두 버그 수정 검증 통과")


if __name__ == "__main__":
    main()
