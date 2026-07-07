"""트리클 vs 홍수 시나리오에서 토큰 사용량 비교 시뮬레이션.

- 순진한 방식(naive): 들어온 모든 raw 로그를 1건씩 AI 호출
- 최적화 방식(queue): 중복제거 + 배치 (TriageQueue)

naive 1건당 토큰은 실제 1회 호출로 측정해 기준값으로 삼고,
최적화 경로는 실제 배치 호출로 토큰을 '실측'해 비교한다.

실행:  python simulate.py
"""
import copy

from triage_service import _SYSTEM_PROMPT, _build_user_prompt, _call_ai
from triage_queue import TriageQueue

# 요금(대략, gemini-2.5-flash): 입력 $0.30/1M, 출력 $2.50/1M
PRICE_IN = 0.30 / 1_000_000
PRICE_OUT = 2.50 / 1_000_000
USD_KRW = 1380


def won(usd: float) -> str:
    return f"${usd:,.2f} (약 {usd*USD_KRW:,.0f}원)"


# ── naive 1건당 기준 토큰 실측 ──────────────────────────────────
def measure_per_log_baseline() -> tuple[int, int]:
    sample = {
        "signature": "SQL Injection", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "3",
        "uri": "/concert/list.do?keyword=%27%20OR%201%3D1%20--",
    }
    _, usage = _call_ai(_SYSTEM_PROMPT, _build_user_prompt(sample))
    return usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0)


# ── 시나리오 데이터 ────────────────────────────────────────────
def flood_window() -> list[dict]:
    """홍수: 동일 브루트포스 200건 + 서로 다른 실제 공격 5건 = 205건이 한 창에 도착."""
    brute = [{
        "signature": "Brute Force", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
        "source": "modsec", "severity": "2", "uri": "/loginAction.do",
    } for _ in range(200)]
    distinct = [
        {"signature": "SQL Injection", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
         "source": "modsec", "severity": "3",
         "uri": "/concert/list.do?keyword=%27%20AND%201%3D2%20AND%20%27%27%3D%27"},
        {"signature": "XSS", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
         "source": "modsec", "severity": "3",
         "uri": "/concert/list.do?keyword=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"},
        {"signature": "Path Traversal", "src_ip": "10.44.44.44", "dest_ip": "10.0.10.2",
         "source": "modsec", "severity": "3",
         "uri": "/qna/downloadFile.do?fileName=../../../../etc/passwd"},
        {"signature": "Command Injection", "src_ip": "10.20.30.40", "dest_ip": "10.0.10.2",
         "source": "modsec", "severity": "3",
         "uri": "/concert/listJson.do;jsessionid=A1B2C3D4E5F6"},  # 실제론 오탐
        {"signature": "SQL Injection", "src_ip": "10.20.30.41", "dest_ip": "10.0.10.2",
         "source": "modsec", "severity": "2",
         "uri": "/faq/selectFaqList.do?page=1&size=10"},          # 실제론 오탐
    ]
    return brute + distinct


def main() -> None:
    print("=" * 68)
    print(" 토큰 사용량 시뮬레이션  (naive 1건씩  vs  큐: 중복제거+배치)")
    print("=" * 68)

    pin, pout = measure_per_log_baseline()
    per_log_total = pin + pout
    per_log_usd = pin * PRICE_IN + pout * PRICE_OUT
    print(f"\n[naive 1건당 실측]  입력 {pin} + 출력 {pout} = {per_log_total} 토큰  → {won(per_log_usd)}")

    # ── 시나리오 1: 트리클 (5분에 1건) ──
    print("\n" + "-" * 68)
    print(" 시나리오 ① 트리클: 5분에 1건  (하루 288건)")
    print("-" * 68)
    daily = 288
    # 트리클은 flush마다 1건 → 배치-of-1 이라 naive와 토큰 동일. naive 기준으로 환산.
    tri_tokens = daily * per_log_total
    tri_usd = daily * per_log_usd
    print(f"  flush당 1건 처리(무한대기 없음). 중복/배치 이점 없음 = naive와 동일.")
    print(f"  하루 {daily}건 → {tri_tokens:,} 토큰/일 → {won(tri_usd)}/일")
    print(f"  월(30일) → {won(tri_usd*30)}   ← 최적화 없이도 무시 가능")

    # ── 시나리오 2: 홍수 (한 창에 205건) ──
    print("\n" + "-" * 68)
    print(" 시나리오 ② 홍수: 한 flush 창에 205건  (브루트포스 200 + 개별공격 5)")
    print("-" * 68)
    window = flood_window()

    # naive: 205건 전부 1건씩 호출 (실측 기준값 × 건수로 환산)
    naive_tokens = len(window) * per_log_total
    naive_usd = len(window) * per_log_usd
    print(f"  [naive]  {len(window)}건 × 1건씩 호출")
    print(f"           AI 호출 {len(window)}회, {naive_tokens:,} 토큰 → {won(naive_usd)}")

    # 최적화: 큐로 중복제거 + 배치 (실제 호출로 실측)
    q = TriageQueue(flush_interval=30, max_batch=10)
    results = q.process_window(copy.deepcopy(window))
    opt_tokens = q.stats["tokens"]
    # 최적화 토큰의 입출력 비율을 몰라 평균요금으로 근사하지 않고, 실측 total에 평균단가 적용
    # (정확 비교 위해 naive와 동일 단가 가정: total 토큰 기준 환산)
    opt_usd_est = opt_tokens * ((pin*PRICE_IN + pout*PRICE_OUT) / per_log_total)
    print(f"  [큐]     중복제거 {q.stats['raw']}건 → 고유 {q.stats['unique']}건")
    print(f"           AI 호출 {q.stats['ai_calls']}회, {opt_tokens:,} 토큰 → {won(opt_usd_est)}")

    cut = (1 - opt_tokens / naive_tokens) * 100 if naive_tokens else 0
    print(f"\n  ▶ 절감: 토큰 {naive_tokens:,} → {opt_tokens:,}  ({cut:.1f}% 감소)")
    tp = sum(1 for r in results if r['triage'].get('is_true_positive'))
    print(f"  ▶ 판정: 정탐 {tp}건 / 총 {len(results)}건 (정탐만 소통플랫폼 전달)")

    print("\n" + "=" * 68)
    print(" 결론: 트리클은 최적화 없이도 저렴 / 홍수는 중복제거가 토큰을 급감시킴")
    print("=" * 68)


if __name__ == "__main__":
    main()
