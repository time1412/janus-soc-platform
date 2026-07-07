"""정/오탐 판별 큐 — 중복제거 + 주기적 flush + 배치.

동작 원리:
  · enqueue()로 분석플랫폼에서 들어온 경보를 버퍼에 쌓는다.
  · 일정 주기(flush_interval초)마다 OR 버퍼가 max_batch건 차면 flush()한다.
  · flush 시: (시그니처+출발지+URI) 동일 건은 1건으로 중복제거 →
    고유 건만 배치로 AI 판별 → 판정을 원래 모든 건에 다시 매핑(fan-out).

이 구조 덕분에:
  - 5분에 1건(트리클): flush마다 1건 → 즉시 처리, 무한대기 없음.
  - 분당 수백건(홍수): 중복제거로 고유 건만 1~소수 호출 → 토큰 급감.

프로덕션 연동(asyncio 백그라운드 루프)은 파일 하단 run_forever() 참고.
시뮬레이션/테스트는 process_window()로 한 flush를 직접 실행한다.
"""
from typing import Any, Callable

from triage_service import _decode, triage_service


def _dedup_key(alert: dict[str, Any]) -> tuple[str, str, str]:
    """중복제거 키 — 같은 출발지가 같은 URI로 같은 시그니처를 또 때린 건 동일 공격으로 간주.

    URI는 디코딩값 기준(인코딩만 다른 동일 페이로드도 합쳐짐).
    페이로드가 실제로 다르면 키가 달라져 별도 판별된다(서로 다른 SQLi는 각각 본다).
    """
    return (
        str(alert.get("signature", "")),
        str(alert.get("src_ip", "")),
        _decode(alert.get("uri", "") or ""),
    )


class TriageQueue:
    def __init__(self, flush_interval: int = 30, max_batch: int = 10,
                 on_true_positive: Callable[[dict], None] | None = None):
        self.flush_interval = flush_interval      # 주기 flush 간격(초)
        self.max_batch = max_batch                # 한 AI 호출당 최대 고유 건수
        self.on_true_positive = on_true_positive  # 정탐 시 콜백(소통플랫폼 전달)
        self._buf: list[dict[str, Any]] = []
        self.stats = {"raw": 0, "unique": 0, "ai_calls": 0, "tokens": 0, "true_positive": 0}

    def enqueue(self, alert: dict[str, Any]) -> None:
        self._buf.append(alert)

    @property
    def pending(self) -> int:
        return len(self._buf)

    def flush(self) -> list[dict[str, Any]]:
        """현재 버퍼를 비우고 판별한다. 버퍼가 비어 있으면 빈 리스트."""
        if not self._buf:
            return []
        batch = self._buf
        self._buf = []
        return self._process(batch)

    def process_window(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """시뮬레이션용 — 한 flush 창에 들어온 경보 묶음을 바로 처리."""
        return self._process(list(alerts))

    def _process(self, batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # ① 중복제거 — 고유 키별 대표 1건만 남김
        unique: dict[tuple, dict] = {}
        order: list[tuple] = []
        for a in batch:
            k = _dedup_key(a)
            if k not in unique:
                unique[k] = a
                order.append(k)
        unique_alerts = [unique[k] for k in order]

        # ② 고유 건을 max_batch 단위로 쪼개 배치 AI 호출
        verdict_by_key: dict[tuple, dict] = {}
        for i in range(0, len(unique_alerts), self.max_batch):
            chunk_keys = order[i:i + self.max_batch]
            chunk = unique_alerts[i:i + self.max_batch]
            verdicts, usage = triage_service.classify_batch(chunk)
            self.stats["ai_calls"] += 1
            self.stats["tokens"] += usage.get("total_tokens", 0)
            for k, v in zip(chunk_keys, verdicts):
                verdict_by_key[k] = v

        # ③ 판정을 원래 모든 건에 다시 매핑(fan-out)
        results = []
        for a in batch:
            v = verdict_by_key[_dedup_key(a)]
            results.append({"alert": a, "triage": v})
            if v.get("is_true_positive"):
                self.stats["true_positive"] += 1
                if self.on_true_positive:
                    self.on_true_positive({"alert": a, "triage": v})

        self.stats["raw"] += len(batch)
        self.stats["unique"] += len(unique_alerts)
        return results


# ------------------------------------------------------------------ #
# 프로덕션 연동 예시 (asyncio 백그라운드 flush 루프)
# ------------------------------------------------------------------ #
async def run_forever(queue: "TriageQueue") -> None:
    """flush_interval초마다 OR 버퍼가 max_batch 차면 flush. (실서비스용 골격)"""
    import asyncio
    while True:
        # max_batch가 빨리 차면 기다리지 않고 즉시 flush
        for _ in range(queue.flush_interval):
            if queue.pending >= queue.max_batch:
                break
            await asyncio.sleep(1)
        queue.flush()
