"""회원가입 + IOC/대장 다중조건 검색 검증."""
import requests

B = "http://localhost:8810"


def main() -> None:
    # ── 회원가입 ──
    u = requests.post(f"{B}/api/signup", json={
        "username": "hong", "password": "1234", "display_name": "홍길동",
        "team": "보안관제팀", "role": "분석가"}).json()
    assert u.get("id"), u
    print(f"✅ 회원가입: {u['display_name']} ({u['team']}/{u['role']})")

    # 중복 아이디
    dup = requests.post(f"{B}/api/signup", json={"username": "hong", "password": "1234", "display_name": "또홍", "team": "정보보호팀"})
    assert dup.status_code == 409
    print(f"✅ 중복 아이디 차단: {dup.status_code} {dup.json()['detail']}")

    # 가입한 계정으로 로그인
    lg = requests.post(f"{B}/api/login", json={"username": "hong", "password": "1234"})
    assert lg.status_code == 200
    print("✅ 가입 계정 로그인 성공")

    u2 = requests.post(f"{B}/api/signup", json={"username": "choi", "password": "5678", "display_name": "최보안", "team": "정보보호팀", "role": "침해대응"}).json()

    # ── 이벤트 적재(서로 다른 IP/날짜) ──
    requests.post(f"{B}/api/events/ingest", json={"events": [
        {"signature": "SQL Injection", "src_ip": "1.1.1.1", "dest_ip": "10.0.10.2",
         "uri": "/a.do?x=1 UNION SELECT", "severity": "3", "ai_verdict": "정탐",
         "ai_confidence": 95, "ai_attack_type": "SQL Injection", "detected_at": "2026-06-01T10:00:00+09:00"},
        {"signature": "XSS", "src_ip": "2.2.2.2", "dest_ip": "10.0.10.2",
         "uri": "/b.do?x=<script>", "severity": "3", "ai_verdict": "정탐",
         "ai_confidence": 90, "ai_attack_type": "XSS", "detected_at": "2026-06-10T10:00:00+09:00"},
    ]}).json()

    # ── 대장 검색: IP ──
    r = requests.get(f"{B}/api/ledger?src_ip=1.1.1.1").json()
    assert r["count"] == 1 and r["rows"][0]["src_ip"] == "1.1.1.1"
    print(f"✅ 대장 IP 검색(1.1.1.1): {r['count']}건")

    # 대장 검색: 날짜 범위 (6/5~6/30 → XSS만)
    r = requests.get(f"{B}/api/ledger?date_from=2026-06-05&date_to=2026-06-30").json()
    sigs = [x["signature"] for x in r["rows"]]
    assert r["count"] == 1 and sigs == ["XSS"], sigs
    print(f"✅ 대장 날짜 검색(6/5~6/30): {r['count']}건 ({sigs})")

    # 대장 검색: 검색어
    r = requests.get(f"{B}/api/ledger?q=union").json()
    assert r["count"] == 1
    print(f"✅ 대장 검색어(union, 대소문자 무관): {r['count']}건")

    # ── IOC 등록 + 날짜 검색 ──
    requests.post(f"{B}/api/iocs", json={"ioc_type": "IP", "value": "1.1.1.1", "first_seen": "2026-06-01", "confidence": 90})
    requests.post(f"{B}/api/iocs", json={"ioc_type": "도메인", "value": "evil.com", "first_seen": "2026-06-10", "confidence": 80})
    r = requests.get(f"{B}/api/iocs?date_from=2026-06-05").json()
    vals = [i["value"] for i in r]
    assert vals == ["evil.com"], vals
    print(f"✅ IOC 날짜 검색(6/5~): {vals}")
    r = requests.get(f"{B}/api/iocs?q=1.1.1").json()
    assert any(i["value"] == "1.1.1.1" for i in r)
    print(f"✅ IOC 값 검색(1.1.1): {[i['value'] for i in r]}")

    print("\n🎉 회원가입 + 검색 검증 통과")


if __name__ == "__main__":
    main()
