"""정/오탐 판별 1건당 실제 토큰 사용량 측정.

OpenRouter 응답의 usage 필드(prompt/completion/total tokens)를 출력한다.
"""
import requests

import config
from triage_service import _SYSTEM_PROMPT, _build_user_prompt

# 대표 케이스 3종 (긴 페이로드 / 짧은 페이로드 / 오탐)
SAMPLES = [
    ("긴 SQLi", {
        "signature": "SQL Injection", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "3",
        "uri": "/concert/list.do?keyword=bts&status=x%27%20AND%201=CTXSYS.DRITHSX.SN(1,(SELECT%20user%20FROM%20dual))%20AND%20%27x%27=%27x",
    }),
    ("짧은 경보", {
        "signature": "Brute Force", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "2", "uri": "/loginAction.do",
    }),
    ("오탐", {
        "signature": "Command Injection", "src_ip": "10.20.30.40", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "3",
        "uri": "/concert/listJson.do;jsessionid=A1B2C3D4E5F6789012345678",
    }),
]


def measure(label: str, alert: dict) -> dict:
    resp = requests.post(
        config.AI_URL,
        headers={"Authorization": f"Bearer {config.AI_API_KEY}", "Content-Type": "application/json"},
        json={
            "model": config.AI_MODEL if "/" in config.AI_MODEL else f"google/{config.AI_MODEL}",
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": _build_user_prompt(alert)},
            ],
            "temperature": 0,
            "usage": {"include": True},  # OpenRouter usage 강제 포함
        },
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()
    return data.get("usage", {})


def main() -> None:
    print("=" * 64)
    print(" 정/오탐 판별 1건당 토큰 사용량 측정")
    print("=" * 64)
    totals = []
    for label, alert in SAMPLES:
        u = measure(label, alert)
        pt = u.get("prompt_tokens", 0)
        ct = u.get("completion_tokens", 0)
        tt = u.get("total_tokens", pt + ct)
        totals.append(tt)
        print(f"\n[{label}]")
        print(f"  입력(prompt)     : {pt:>5} 토큰")
        print(f"  출력(completion) : {ct:>5} 토큰")
        print(f"  합계(total)      : {tt:>5} 토큰")

    avg = sum(totals) / len(totals)
    print("\n" + "=" * 64)
    print(f" 평균: 약 {avg:.0f} 토큰/건")
    print("=" * 64)


if __name__ == "__main__":
    main()
