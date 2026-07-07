# -*- coding: utf-8 -*-
"""시간 윈도우 머지 키 검증: 같은 윈도우=병합, 다른 윈도우=신규."""
import config
from triage_service import _dedup_key

print(f"윈도우: {config.TRIAGE_MERGE_WINDOW_MIN}분")

waf = {"signature": "XSS", "src_ip": "10.44.44.44", "_time": "2026-06-13T10:00:00.000+09:00"}
snort = {"signature": "XSS (Snort)", "src_ip": "10.44.44.44", "_time": "2026-06-13T10:05:00.000+09:00"}  # +5분, 다른 소스
later = {"signature": "XSS", "src_ip": "10.44.44.44", "_time": "2026-06-13T10:40:00.000+09:00"}  # +40분(새 윈도우)
other_ip = {"signature": "XSS", "src_ip": "1.2.3.4", "_time": "2026-06-13T10:00:00.000+09:00"}

print("WAF       :", _dedup_key(waf))
print("Snort(+5m):", _dedup_key(snort))
print("XSS(+40m) :", _dedup_key(later))
print("다른 IP   :", _dedup_key(other_ip))

assert _dedup_key(waf) == _dedup_key(snort), "동일 윈도우 크로스소스 병합 실패"
assert _dedup_key(waf) != _dedup_key(later), "새 윈도우 분리 실패(신규 공격 누락 버그)"
assert _dedup_key(waf) != _dedup_key(other_ip), "다른 IP 분리 실패"
print("\nOK — 같은 윈도우(±)는 병합, 30분 경과 새 공격은 신규 인시던트로 분리")
