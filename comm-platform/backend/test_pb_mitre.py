"""플레이북 관리(CRUD) + 티켓 적용 + MITRE 조회 검증."""
import requests

B = "http://localhost:8810"


def main() -> None:
    u = requests.post(f"{B}/api/signup", json={"username": "pbadmin", "password": "1234", "display_name": "PB관리", "team": "정보보호팀"}).json()
    if not u.get("id"):
        u = requests.post(f"{B}/api/login", json={"username": "pbadmin", "password": "1234"}).json()

    # 기본 시드 3개
    pbs = requests.get(f"{B}/api/playbooks").json()
    print(f"✅ 기본 플레이북 {len(pbs)}개: {[p['name'] for p in pbs]}")

    # 생성
    created = requests.post(f"{B}/api/playbooks", json={
        "name": "랜섬웨어 대응", "description": "암호화형 침해",
        "steps": ["감염 호스트 격리", "백업 무결성 확인", "복호화 가능성 조사", "경영진·법무 보고"]}).json()
    assert created["id"] and len(created["steps"]) == 4
    print(f"✅ 플레이북 생성: {created['name']} ({len(created['steps'])}단계)")

    # 중복 이름 거부
    dup = requests.post(f"{B}/api/playbooks", json={"name": "랜섬웨어 대응", "steps": ["x"]})
    assert dup.status_code == 409
    print(f"✅ 중복 이름 거부: {dup.status_code}")

    # 수정
    upd = requests.put(f"{B}/api/playbooks/{created['id']}", json={
        "name": "랜섬웨어 대응", "description": "수정됨", "steps": ["격리", "백업확인", "보고", "복구"]}).json()
    assert upd["description"] == "수정됨" and len(upd["steps"]) == 4
    print(f"✅ 플레이북 수정: 설명='{upd['description']}', 단계 {len(upd['steps'])}")

    # 티켓에 새 플레이북 적용 (DB 기반)
    t = requests.post(f"{B}/api/events/ticket", json={"user_id": u["id"], "signature": "랜섬 의심", "severity": "3"}).json()
    d = requests.post(f"{B}/api/events/{t['id']}/playbook", json={"user_id": u["id"], "key": "랜섬웨어 대응"}).json()
    assert len(d["tasks"]) == 4
    print(f"✅ 티켓에 DB 플레이북 적용: 작업 {len(d['tasks'])}개 ({[x['title'] for x in d['tasks']]})")

    # 삭제
    r = requests.delete(f"{B}/api/playbooks/{created['id']}")
    assert r.json().get("deleted")
    print("✅ 플레이북 삭제")

    # MITRE 조회
    mt = requests.get(f"{B}/api/mitre").json()
    assert mt["count"] >= 50 and "초기 침투" in mt["tactics"]
    t1190 = [x for x in mt["techniques"] if x["id"] == "T1190"][0]
    assert "attack.mitre.org/techniques/T1190" in t1190["url"]
    print(f"✅ MITRE 조회: {mt['count']}개 기법, 전술 {len(mt['tactics'])}종")
    print(f"   예: {t1190['id']} {t1190['name']} [{t1190['tactic']}] → {t1190['url']}")
    sub = [x for x in mt["techniques"] if x["id"] == "T1110.001"][0]
    assert "T1110/001" in sub["url"]
    print(f"   하위기법 URL 정상: {sub['id']} → {sub['url']}")

    print("\n🎉 플레이북 관리 + MITRE 조회 검증 통과")


if __name__ == "__main__":
    main()
