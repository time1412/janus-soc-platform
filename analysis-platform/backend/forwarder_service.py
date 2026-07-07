"""정탐 이벤트 전달 서비스 — 분석플랫폼 → 소통플랫폼.

정·오탐 자동 판정 결과 중 '정탐'만 골라 소통플랫폼(/api/events/ingest)으로 전달한다.
- 동일 경보(시그니처+출발지IP+디코딩URI) 중복 전달 방지: 전송한 키를 영구 캐시
  (storage/forwarded_keys.json)에 기록해 같은 정탐이 매 주기마다 재전송되지 않게 한다.
- 전송 실패 시 키를 기록하지 않으므로 다음 주기에 자동 재시도한다.
"""
import json
from typing import Any

import requests

import config
from triage_service import _dedup_key, _decode, _extract_indicator

_SENT_FILE = config.BASE_DIR / "storage" / "forwarded_keys.json"
_INGEST_PATH = "/api/events/ingest"

# ── AI 판정 기반 위험도(severity) 재산정 ─────────────────────────────
# 위험도는 탐지 '규칙 분류'에서 나와, 규칙이 태그를 못 붙인 공격(예: webshell이
# 'WAF Anomaly'로 분류 → 기본 낮음)은 실제 위협보다 낮게 잡힌다.
# AI가 페이로드를 직접 읽고 내린 판정으로 위험도를 보정한다(상향 only, 절대 하향 안 함).
# 3=고위험, 2=주의, 1=낮음.
_CRIT_KEYWORDS = (   # 시스템 장악·데이터 유출급 → 고위험(3)
    "rce", "command", "명령", "webshell", "웹쉘", "shell", "백도어", "backdoor",
    "upload", "업로드", "sql", "injection", "주입", "deserial", "역직렬", "ssti",
    "template", "xxe", "ssrf", "lfi", "rfi", "traversal", "탈취", "c2", "implant",
)
_MED_KEYWORDS = (   # XSS·세션·리다이렉트 등 → 주의(2)
    "xss", "cross", "스크립트", "script", "redirect", "리다이렉트",
    "session", "세션", "fixation", "csrf",
)


def _severity_from_ai(base: str, triage: dict[str, Any]) -> str:
    """원본 severity를 AI 정탐 판정·공격유형·신뢰도로 보정(상향 only)."""
    try:
        base_n = int(str(base))
    except (TypeError, ValueError):
        base_n = 2
    if not triage.get("is_true_positive"):
        return str(base_n)
    conf = int(triage.get("confidence") or 0)
    blob = " ".join([
        str(triage.get("attack_type") or ""),
        str(triage.get("reasoning") or ""),
        " ".join(str(x) for x in (triage.get("indicators") or [])),
    ]).lower()
    ai_sev = 0
    if conf >= 60 and any(k in blob for k in _CRIT_KEYWORDS):
        ai_sev = 3                       # 고위험 공격을 고신뢰로 정탐
    elif any(k in blob for k in _MED_KEYWORDS):
        ai_sev = 2                       # 중위험 공격
    elif conf >= 80:
        ai_sev = 2                       # 그 외에도 고신뢰 정탐이면 최소 '주의'
    return str(max(base_n, ai_sev))      # 원본보다 낮추지 않음


def _load_sent() -> set[str]:
    try:
        return set(json.loads(_SENT_FILE.read_text(encoding="utf-8")))
    except Exception:
        return set()


def _save_sent(sent: set[str]) -> None:
    try:
        _SENT_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SENT_FILE.write_text(json.dumps(sorted(sent), ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _attack_payload(alert: dict[str, Any], triage: dict[str, Any]) -> str:
    """판정에 실제로 쓰인 공격 페이로드를 사람이 보기 좋게 구성한다.

    POST 공격(XSS 등)은 페이로드가 URI가 아니라 본문/근거(evidence)에 있어, uri만으로는
    '일부분'만 보인다. 디코딩 payload·URI 쿼리·modsec 본문 추출·상관 evidence·LLM 인용을 모은다.
    """
    parts: list[str] = []
    seen: set[str] = set()

    def add(s: Any) -> None:
        s = str(s or "").strip()
        if s and s not in seen:
            seen.add(s)
            parts.append(s)

    add(_decode(str(alert.get("payload") or "")))            # 디코딩된 payload 필드
    uri = _decode(str(alert.get("uri") or ""))
    if "?" in uri:                                            # GET 공격: 쿼리스트링이 페이로드
        add(uri)
    add(_extract_indicator(str(alert.get("body") or "")))    # modsec 본문에서 공격 구문 추출
    for e in (alert.get("evidence") or [])[:6]:              # 상관탐지 기여 이벤트들의 페이로드
        if isinstance(e, dict):
            p = str(e.get("payload") or e.get("injected_params") or "").strip()
            p = "" if p.startswith("(") else _decode(p)      # 플레이스홀더 제외
            add(p or _extract_indicator(str(e.get("request_raw") or e.get("raw") or "")))
    for ind in (triage.get("indicators") or [])[:6]:         # LLM이 인용한 근거 조각
        add(ind)
    return "\n".join(parts)[:3000]


def _to_ingest_event(alert: dict[str, Any], triage: dict[str, Any], dup_count: int) -> dict[str, Any]:
    """분석플랫폼 경보 + 판정 결과를 소통플랫폼 IngestEvent 페이로드로 변환."""
    sig = str(alert.get("signature") or alert.get("sourcetype") or "이벤트")
    reasoning = str(triage.get("reasoning") or "")
    # 분산 DDoS: 출발지가 다수면 캠페인 규모를 근거에 명시(출발지는 dest 기준으로 1건에 병합됨)
    src_count = int(alert.get("merged_src_count") or 0)
    if "ddos" in sig.lower() and src_count > 1:
        reasoning = (f"[분산 DDoS 캠페인] 출발지 {src_count}개 → 대상 "
                     f"{alert.get('dest_ip') or '-'} (탐지 {dup_count}건 집계). " + reasoning)
    return {
        "signature": sig,
        "src_ip": str(alert.get("src_ip") or ""),
        "dest_ip": str(alert.get("dest_ip") or ""),
        "src_port": str(alert.get("src_port") or ""),
        "dest_port": str(alert.get("dest_port") or ""),
        "asset": str(alert.get("asset") or ""),   # 호스트형 탐지의 피해 자산(호스트명)
        "uri": str(alert.get("uri") or ""),
        "payload": _attack_payload(alert, triage),

        # 위험도: 원본 규칙 분류값을 AI 판정으로 보정(상향). webshell 등 규칙이 놓친 위협 반영.
        "severity": _severity_from_ai(alert.get("severity") or "2", triage),
        "source": str(alert.get("source") or ""),
        # 상관룰이 큐레이션한 MITRE(notable.mitre). 소통은 이걸 권위값으로 쓰고 없으면 키워드 추론.
        "mitre": str(alert.get("mitre") or ""),
        "detected_at": str(alert.get("_time") or alert.get("detected_at") or ""),
        "ai_verdict": str(triage.get("verdict") or "정탐"),
        "ai_confidence": int(triage.get("confidence") or 0),
        "ai_attack_type": str(triage.get("attack_type") or ""),
        "ai_reasoning": reasoning,
        "dup_count": dup_count,
    }


class ForwarderService:
    def __init__(self) -> None:
        self._sent = _load_sent()   # 이미 전달한 dedup_key 집합

    def forward_true_positives(self, triage_result: dict[str, Any]) -> dict[str, Any]:
        """auto_triage 결과에서 '정탐'만 골라 소통플랫폼으로 전달(중복 제외).

        반환: {forwarded, skipped_dup, total_tp, ids, error?}
        """
        if not config.COMM_FORWARD_ENABLED:
            return {"forwarded": 0, "skipped_dup": 0, "total_tp": 0, "ids": [], "disabled": True}

        results = triage_result.get("results", [])
        # auto_triage가 이미 상관 그룹(유형+IP)으로 1행씩 병합해 줌. 정탐만 추림.
        groups: dict[str, dict[str, Any]] = {}
        for r in results:
            t = r.get("triage", {})
            if not t.get("is_true_positive"):
                continue
            alert = r.get("alert", {})
            k = _dedup_key(alert)
            g = groups.get(k)
            cnt = int(alert.get("merged_count", 1) or 1)   # 병합된 원본 경보 수
            if g:
                g["count"] += cnt
            else:
                groups[k] = {"alert": alert, "triage": t, "count": cnt}

        total_tp = len(groups)
        new = {k: g for k, g in groups.items() if k not in self._sent}
        if not new:
            return {"forwarded": 0, "skipped_dup": total_tp, "total_tp": total_tp, "ids": []}

        payload = {"events": [_to_ingest_event(g["alert"], g["triage"], g["count"]) for g in new.values()]}
        try:
            resp = requests.post(
                config.COMM_PLATFORM_URL.rstrip("/") + _INGEST_PATH,
                json=payload, timeout=15,
            )
            resp.raise_for_status()
            body = resp.json()
        except Exception as exc:
            # 실패 시 키를 기록하지 않음 → 다음 주기에 재시도
            return {"forwarded": 0, "skipped_dup": total_tp - len(new), "total_tp": total_tp,
                    "ids": [], "error": str(exc)}

        # 전송 성공 → 키 기록(재전송 방지)
        self._sent |= set(new.keys())
        _save_sent(self._sent)
        return {
            "forwarded": body.get("ingested", len(new)),
            "skipped_dup": total_tp - len(new),
            "total_tp": total_tp,
            "ids": body.get("ids", []),
        }


forwarder_service = ForwarderService()
