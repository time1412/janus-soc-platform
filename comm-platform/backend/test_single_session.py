"""중복 로그인 방지(단일 세션) 검증 — 같은 user_id 재접속 시 기존 세션 강제 종료."""
import json
import time

import requests
from websockets.sync.client import connect

WS = "ws://localhost:8810/ws"
B = "http://localhost:8810"


def main() -> None:
    # 같은 계정(user_id=2) 첫 접속
    ws1 = connect(f"{WS}?user_id=2")
    time.sleep(0.3)
    assert 2 in requests.get(f"{B}/api/presence").json()["online"]
    print("✅ 세션A(user2) 접속")

    # 같은 계정으로 두 번째 접속 → 세션A에 force_logout 와야 함
    ws2 = connect(f"{WS}?user_id=2")
    forced = False
    try:
        while True:
            d = json.loads(ws1.recv(timeout=2))
            if d.get("type") == "force_logout":
                forced = True
                print(f"✅ 세션A가 강제 로그아웃 수신: \"{d.get('reason')}\"")
                break
    except Exception:
        pass
    assert forced, "기존 세션이 force_logout을 받지 못함"

    # 여전히 user2는 온라인(세션B가 살아있음)
    time.sleep(0.3)
    online = requests.get(f"{B}/api/presence").json()["online"]
    assert 2 in online, online
    print(f"✅ 세션B는 유지(온라인 {online}) — 마지막 로그인만 활성")

    # 다른 계정(user4)은 영향 없음
    ws4 = connect(f"{WS}?user_id=4")
    time.sleep(0.3)
    online = requests.get(f"{B}/api/presence").json()["online"]
    assert 2 in online and 4 in online, online
    print(f"✅ 다른 계정(user4)은 영향 없음 (온라인 {online})")

    ws2.close(); ws4.close()
    try:
        ws1.close()
    except Exception:
        pass
    time.sleep(0.3)
    print(f"✅ 종료 후 온라인: {requests.get(f'{B}/api/presence').json()['online']}")
    print("\n🎉 중복 로그인 방지(단일 세션) 검증 통과")


if __name__ == "__main__":
    main()
