"""사내 부서 메일(외부 SMTP, 드라이런) + 인앱 메일 공존 검증."""
import requests

B = "http://localhost:8810"


def main() -> None:
    snd = requests.post(f"{B}/api/signup", json={"username": "mailer", "password": "1234", "display_name": "메일러", "team": "정보보호팀"}).json()
    if not snd.get("id"):
        snd = requests.post(f"{B}/api/login", json={"username": "mailer", "password": "1234"}).json()

    # 부서/연락처
    depts = requests.get(f"{B}/api/departments").json()["departments"]
    assert "개발팀" in depts
    print(f"✅ 부서 목록: {depts[:4]} ...")
    contacts = requests.get(f"{B}/api/contacts").json()
    dev = [c for c in contacts if c["dept"] == "개발팀"][0]
    print(f"✅ 주소록 연락처: {dev['name']} · {dev['dept']} ({dev['email']})")

    # ── 외부 부서(이메일) 발송 — SMTP 미설정이라 드라이런 ──
    res = requests.post(f"{B}/api/mail", json={
        "sender_id": snd["id"], "recipient_email": dev["email"], "recipient_name": dev["name"],
        "recipient_dept": dev["dept"], "subject": "[보안] 취약점 조치 요청", "body": "개발팀 확인 부탁드립니다."}).json()
    assert res["channel"] == "email" and res["ok"], res
    print(f"✅ 사내 부서 메일 발송: channel={res['channel']}, to={res['to']}, 결과=\"{res['detail']}\"")

    # 보낸함에 외부 메일 기록 (recipient=None, recipient_email 채워짐)
    sent = requests.get(f"{B}/api/mail/sent?user_id={snd['id']}").json()
    ext = [m for m in sent if m["channel"] == "email"]
    assert ext and ext[0]["recipient_email"] == dev["email"] and ext[0]["recipient"] is None
    print(f"✅ 보낸함 외부 메일 기록: → {ext[0]['recipient_name']}({ext[0]['recipient_dept']}) <{ext[0]['recipient_email']}>")

    # ── 인앱 발송도 여전히 동작 ──
    rcp = requests.post(f"{B}/api/signup", json={"username": "inapp1", "password": "1234", "display_name": "인앱수신", "team": "보안관제팀"}).json()
    if not rcp.get("id"):
        rcp = requests.post(f"{B}/api/login", json={"username": "inapp1", "password": "1234"}).json()
    r2 = requests.post(f"{B}/api/mail", json={"sender_id": snd["id"], "recipient_id": rcp["id"], "subject": "인앱 테스트", "body": "내부 메시지"}).json()
    assert r2["channel"] == "inapp"
    inbox = requests.get(f"{B}/api/mail/inbox?user_id={rcp['id']}").json()
    assert any(m["channel"] == "inapp" and m["subject"] == "인앱 테스트" for m in inbox)
    print(f"✅ 인앱 메일 발송/수신 정상 (받은편지함 {len(inbox)}건)")

    # 연락처 추가
    c = requests.post(f"{B}/api/contacts", json={"name": "신규담당", "email": "new@company.local", "dept": "운영팀"}).json()
    assert c.get("id")
    print(f"✅ 연락처 추가: {c['name']} ({c['email']})")

    print("\n🎉 사내 부서 메일(하이브리드) 검증 통과")


if __name__ == "__main__":
    main()
