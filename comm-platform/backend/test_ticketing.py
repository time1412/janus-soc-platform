"""SOC 티켓팅 검증: 수동생성·티켓번호·우선순위·SLA·태그/MITRE·첨부."""
import io
from datetime import datetime, timezone

import requests

B = "http://localhost:8810"
PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108020000009077"
                    "53de0000000c4944415408d7636060606000000005000157a1d0fe0000000049454e44ae426082")


def main() -> None:
    u = requests.post(f"{B}/api/signup", json={"username": "tkt", "password": "1234", "display_name": "티켓담당", "team": "보안관제팀"}).json()
    if not u.get("id"):
        u = requests.post(f"{B}/api/login", json={"username": "tkt", "password": "1234"}).json()

    # ── 자동 수신(ingest)도 티켓번호/SLA 부여 ──
    ing = requests.post(f"{B}/api/events/ingest", json={"events": [{
        "signature": "SQL Injection", "src_ip": "10.44.44.44", "severity": "3",
        "ai_verdict": "정탐", "ai_confidence": 95, "ai_attack_type": "SQL Injection",
        "detected_at": "2026-06-12T10:00:00+09:00"}]}).json()
    auto = requests.get(f"{B}/api/events/{ing['ids'][0]}").json()
    assert auto["ticket_no"].startswith("INC-") and auto["priority"] == "P1" and auto["due_at"]
    print(f"✅ 자동수신 티켓: {auto['ticket_no']} · {auto['priority']} · SLA {auto['due_at'][:16]} · origin={auto['origin']}")

    # ── 수동 티켓 생성 ──
    t = requests.post(f"{B}/api/events/ticket", json={
        "user_id": u["id"], "signature": "의심스러운 관리자 로그인", "severity": "2",
        "src_ip": "10.0.150.5", "description": "DEV망에서 비정상 시도",
        "tags": "내부, 계정", "mitre": "T1078"}).json()
    tid = t["id"]
    assert t["origin"] == "수동" and t["ticket_no"].startswith("INC-") and t["priority"] == "P2"
    print(f"✅ 수동 티켓 생성: {t['ticket_no']} · {t['priority']} · 태그={t['tags']} · MITRE={t['mitre']}")

    # ── 우선순위 변경 → SLA 재계산 ──
    before_due = t["due_at"]
    t2 = requests.post(f"{B}/api/events/{tid}/priority", json={"user_id": u["id"], "priority": "P1"}).json()
    assert t2["priority"] == "P1" and t2["due_at"] != before_due
    print(f"✅ 우선순위 P2→P1, SLA 재계산: {before_due[:16]} → {t2['due_at'][:16]}")

    # ── 태그/MITRE 수정 ──
    t3 = requests.patch(f"{B}/api/events/{tid}/meta", json={"user_id": u["id"], "tags": "내부, 계정, 긴급", "mitre": "T1078, T1110"}).json()
    assert "긴급" in t3["tags"] and "T1110" in t3["mitre"]
    print(f"✅ 분류 수정: 태그={t3['tags']} · MITRE={t3['mitre']}")

    # ── 첨부 ──
    up = requests.post(f"{B}/api/upload", files={"file": ("evidence.png", io.BytesIO(PNG), "image/png")}).json()
    t4 = requests.post(f"{B}/api/events/{tid}/attachments", json={"user_id": u["id"], "url": up["url"], "name": "evidence.png", "size": up["size"]}).json()
    assert len(t4["attachments"]) == 1 and t4["attachments"][0]["name"] == "evidence.png"
    print(f"✅ 첨부 추가: {t4['attachments'][0]['name']} ({t4['attachments'][0]['size']}B)")

    # 이력에 티켓생성/우선순위/분류수정/첨부 기록
    actions = [h["action"] for h in t4["history"]]
    for a in ["티켓생성", "우선순위", "분류수정", "첨부"]:
        assert a in actions, (a, actions)
    print(f"✅ 처리 이력: {actions}")

    print("\n🎉 SOC 티켓팅 검증 통과")


if __name__ == "__main__":
    main()
