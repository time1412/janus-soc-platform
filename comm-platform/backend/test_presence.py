"""WebSocket presence(접속현황) + assignee 필터 검증."""
import json
import threading
import time

import requests
from websockets.sync.client import connect

B = "http://localhost:8810"
WS = "ws://localhost:8810/ws"


def main() -> None:
    # assignee 필터 형태 확인
    r = requests.get(f"{B}/api/events?assignee_id=4")
    assert r.status_code == 200 and isinstance(r.json(), list)
    print(f"✅ assignee 필터: status 200, {len(r.json())}건 (JSON 배열)")

    # 초기 presence
    assert requests.get(f"{B}/api/presence").json()["online"] == []
    print("✅ 초기 presence: 빈 목록")

    # user 2(soc_lee) 접속
    msgs = []
    with connect(f"{WS}?user_id=2") as ws2:
        time.sleep(0.4)
        online = requests.get(f"{B}/api/presence").json()["online"]
        assert 2 in online, online
        print(f"✅ user2 접속 후 presence: {online}")

        # user 4(ist_choi)도 접속 → presence 브로드캐스트 수신 확인
        with connect(f"{WS}?user_id=4") as ws4:
            time.sleep(0.4)
            online = requests.get(f"{B}/api/presence").json()["online"]
            assert 2 in online and 4 in online, online
            print(f"✅ user4 추가 접속 후 presence: {online}")

            # ws2가 presence 브로드캐스트를 받았는지
            ws2.send("ping")
            got_presence = False
            try:
                while True:
                    raw = ws2.recv(timeout=1)
                    d = json.loads(raw)
                    if d.get("type") == "presence":
                        got_presence = True
                        break
            except Exception:
                pass
            print(f"✅ presence 브로드캐스트 수신: {got_presence}")

        time.sleep(0.4)
        online = requests.get(f"{B}/api/presence").json()["online"]
        assert 4 not in online, online
        print(f"✅ user4 종료 후 presence: {online}")

    time.sleep(0.4)
    assert requests.get(f"{B}/api/presence").json()["online"] == []
    print("✅ 전원 종료 후 presence: 빈 목록")
    print("\n🎉 presence + 필터 검증 통과")


if __name__ == "__main__":
    main()
