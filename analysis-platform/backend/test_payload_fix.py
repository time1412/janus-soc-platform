"""검증: ① POST 본문 SQLi가 정탐으로 판정 ② 같은 공격의 GET/POST가 한 건으로 dedup."""
import requests
from triage_service import _dedup_key, _payload_fingerprint

B = "http://localhost:8800"

# ── ① QnA POST SQLi → 정탐이어야 함 (이전엔 본문이 안 보여 오탐) ──
qna = {"signature": "SQL Injection", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
       "uri": "/qna/searchQnaList.do", "severity": "3", "source": "modsec",
       "body": "&keyword=test' UNION SELECT null,EMAIL,NAME,null FROM MEMBERS--"}
r = requests.post(f"{B}/api/triage", json={"events": [qna]}, timeout=120).json()
t = r["results"][0]["triage"]
print(f"① QnA POST SQLi → {t['verdict']} {t['confidence']}%  ({t['attack_type']})")
print(f"   근거: {t['reasoning']}")

# ── ② 로그인 XSS: GET(쿼리)과 POST(본문+정상필드)가 같은 키로 묶이는가 ──
get_xss = {"signature": "XSS", "src_ip": "10.44.44.44",
           "uri": '/loginForm.do?returnUrl="><script>alert(document.cookie)</script>'}
post_xss = {"signature": "XSS", "src_ip": "10.44.44.44", "uri": "/loginAction.do",
            "body": 'userId=admin&password=1234&returnUrl="><script>alert(document.cookie)</script>'}
kg, kp = _dedup_key(get_xss), _dedup_key(post_xss)
print(f"\n② GET  지문: {_payload_fingerprint(get_xss)}")
print(f"   POST 지문: {_payload_fingerprint(post_xss)}")
print(f"   GET  key = {kg}")
print(f"   POST key = {kp}")
print(f"   → 동일 키로 병합? {kg == kp}")

# ── ③ 서로 다른 공격은 안 묶여야 함 ──
other = {"signature": "SQL Injection", "src_ip": "10.44.44.44", "uri": "/qna/searchQnaList.do",
         "body": "&keyword=test' OR 1=1--"}
print(f"\n③ 다른 payload(QnA UNION vs OR 1=1) 분리? {_dedup_key(qna) != _dedup_key(other)}")

assert t["verdict"] == "정탐", f"QnA SQLi가 여전히 {t['verdict']}"
assert kg == kp, "GET/POST가 병합되지 않음"
assert _dedup_key(qna) != _dedup_key(other), "다른 공격이 잘못 병합됨"
print("\nOK — SQLi 정탐 복구 + GET/POST 병합 + 다른 공격 분리 모두 확인")
