"""IOC 관리 + 탐지이력 대장 검증."""
import requests

B = "http://localhost:8810"


def main() -> None:
    user = requests.post(f"{B}/api/login", json={"username": "ist_choi", "password": "1234"}).json()

    # 이벤트 하나 골라 IOC 자동 추출
    ev = requests.get(f"{B}/api/events").json()[0]
    iocs = requests.post(f"{B}/api/iocs/extract/{ev['id']}?user_id={user['id']}").json()
    print(f"✅ 이벤트#{ev['id']}({ev['signature']})에서 IOC 자동 추출: {len(iocs)}건")
    for i in iocs:
        print(f"    · [{i['ioc_type']}] {i['value'][:60]} (출처 이벤트#{i['source_event_id']})")

    # 수동 IOC 추가
    m = requests.post(f"{B}/api/iocs", json={
        "ioc_type": "도메인", "value": "evil-c2.example.com", "severity": "3",
        "confidence": 90, "description": "C2 서버 도메인", "created_by_id": user["id"],
    }).json()
    print(f"✅ 수동 IOC 등록: [{m['ioc_type']}] {m['value']}")

    # 상태 변경 (차단완료)
    upd = requests.patch(f"{B}/api/iocs/{m['id']}", json={"status": "차단완료"}).json()
    assert upd["status"] == "차단완료"
    print(f"✅ IOC 상태 변경: {upd['status']}")

    # 중복 등록 → upsert(신규 생성 안 됨)
    before = requests.get(f"{B}/api/iocs/stats").json()["total"]
    requests.post(f"{B}/api/iocs", json={"ioc_type": "도메인", "value": "evil-c2.example.com"})
    after = requests.get(f"{B}/api/iocs/stats").json()["total"]
    assert before == after, "중복 IOC는 새로 생기면 안 됨"
    print(f"✅ 중복 등록 방지(upsert): 총 {after}건 유지")

    # 필터 조회
    ips = requests.get(f"{B}/api/iocs?ioc_type=IP").json()
    print(f"✅ 유형 필터(IP): {len(ips)}건")

    # 탐지이력 대장
    led = requests.get(f"{B}/api/ledger").json()
    print(f"✅ 탐지이력 대장: {led['count']}건")
    if led["rows"]:
        r = led["rows"][0]
        print(f"    예시: #{r['id']} {r['signature']} / 상태={r['status']} / 결정자={r['decided_by'] or '-'}")

    # CSV 내보내기
    csv = requests.get(f"{B}/api/ledger/export")
    assert csv.status_code == 200 and "번호" in csv.text
    print(f"✅ CSV 내보내기: {len(csv.text)} bytes, 헤더 OK")

    print("\n🎉 IOC + 대장 검증 통과")


if __name__ == "__main__":
    main()
