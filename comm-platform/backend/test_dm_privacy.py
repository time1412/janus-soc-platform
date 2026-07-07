"""DM 비공개 검증 — 발신자·수신자만 WS 수신, 제3자(bystander)는 못 받음."""
import json
import threading
import time

import requests
from websockets.sync.client import connect

B = "http://localhost:8810"
WS = "ws://localhost:8810/ws"


def login_or_signup(uname, name, team):
    u = requests.post(f"{B}/api/signup", json={"username": uname, "password": "1234", "display_name": name, "team": team}).json()
    if not u.get("id"):
        u = requests.post(f"{B}/api/login", json={"username": uname, "password": "1234"}).json()
    return u


def listen(uid, store, key):
    try:
        with connect(f"{WS}?user_id={uid}") as ws:
            store[key + "_ready"] = True
            while True:
                d = json.loads(ws.recv(timeout=4))
                if d.get("type") == "dm":
                    store[key] = d["message"]["body"]
                    return
    except Exception:
        pass


def main() -> None:
    a = login_or_signup("priv_a", "발신A", "보안관제팀")
    b = login_or_signup("priv_b", "수신B", "정보보호팀")
    c = login_or_signup("priv_c", "제3자C", "보안관제팀")

    store = {}
    ta = threading.Thread(target=listen, args=(a["id"], store, "A")); ta.start()
    tb = threading.Thread(target=listen, args=(b["id"], store, "B")); tb.start()
    tc = threading.Thread(target=listen, args=(c["id"], store, "C")); tc.start()
    time.sleep(0.8)  # 소켓 연결 대기

    requests.post(f"{B}/api/dm", json={"sender_id": a["id"], "recipient_id": b["id"], "body": "비밀 메시지"})
    ta.join(timeout=5); tb.join(timeout=5); tc.join(timeout=5)

    print(f"발신자 A 수신: {store.get('A')!r}")
    print(f"수신자 B 수신: {store.get('B')!r}")
    print(f"제3자 C 수신: {store.get('C')!r}")
    assert store.get("B") == "비밀 메시지", "수신자 B가 받아야 함"
    assert store.get("A") == "비밀 메시지", "발신자 A도 (본인 에코) 받아야 함"
    assert store.get("C") is None, "제3자 C는 받으면 안 됨 (프라이버시 누설)"
    print("\n🎉 DM 비공개 검증 통과 — 발신/수신자만 수신, 제3자 차단")


if __name__ == "__main__":
    main()
