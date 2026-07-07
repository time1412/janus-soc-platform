"""신뢰도 근거(confidence_reason) + 캐시(재판정 방지) 확인."""
import requests

B = "http://localhost:8800"
evts = [{"signature": "SQL Injection", "src_ip": "9.9.9.9",
         "uri": "/x.do?q=%27%20UNION%20SELECT%20pw%20FROM%20users--", "severity": "3", "source": "modsec"}]

r1 = requests.post(f"{B}/api/triage", json={"events": evts}, timeout=120).json()
t = r1["results"][0]["triage"]
print("1차 신규판정:", r1["counts"]["신규판정"])
print("verdict:", t["verdict"], t["confidence"], "%")
print("confidence_reason:", t.get("confidence_reason"))

r2 = requests.post(f"{B}/api/triage", json={"events": evts}, timeout=120).json()
print("2차 신규판정(캐시면 0):", r2["counts"]["신규판정"])
assert r2["counts"]["신규판정"] == 0, "캐시 미동작"
assert t.get("confidence_reason"), "confidence_reason 누락"
print("\nOK — 신뢰도 근거 표기 + 캐시 동작 확인")
