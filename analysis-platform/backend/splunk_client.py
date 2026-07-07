"""스플렁크 REST API 호출 담당.

ESM(10.0.200.201:8089)의 search/jobs 엔드포인트에 검색을 던지고
결과(JSON)를 회수한다. 토큰이 있으면 토큰 인증, 없으면 basic 인증을 쓴다.
"""
import json
import re
import time
from typing import Any

import requests
import urllib3

import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")


def _first_ip(s: str) -> str:
    """문자열에서 첫 IP만 추출(없으면 원문 반환)."""
    m = _IP_RE.search(str(s or ""))
    return m.group(0) if m else str(s or "")


def _has_ip(s: Any) -> bool:
    return bool(_IP_RE.search(str(s or "")))


# Snort 등 raw 로그의 'IP:port -> IP:port'(출발→목적)에서 포트 추출
_PORTPAIR_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")
# ModSecurity 감사로그 A섹션 '[ts] id CLIENT_IP CLIENT_PORT SERVER_IP SERVER_PORT'
_MODSEC_A_RE = re.compile(
    r"---A--\s*\n\[[^\]]*\]\s+\S+\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,5})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,5})")


def _ports_from_raw(raw: Any, src_ip: str = "", dest_ip: str = "") -> tuple[str, str]:
    """raw 로그에서 (출발지 포트, 목적지 포트)를 추출. IP가 맞으면 방향까지 보정.

    두 형식 지원: Snort 'ip:port -> ip:port' / ModSecurity A섹션 'ip port ip port'.
    """
    s = str(raw or "")
    m = _PORTPAIR_RE.search(s) or _MODSEC_A_RE.search(s)
    if not m:
        return "", ""
    a_ip, a_port, b_ip, b_port = m.group(1), m.group(2), m.group(3), m.group(4)
    sp, dp = a_port, b_port                 # 기본: 'src -> dst' 순서
    if src_ip and src_ip == b_ip:           # 출발지가 raw 뒤쪽이면 스왑
        sp, dp = b_port, a_port
    elif dest_ip and dest_ip == a_ip:       # 목적지가 raw 앞쪽이면 스왑
        sp, dp = b_port, a_port
    return sp, dp


def _ports_from_evidence(ev: list, src_ip: str = "", dest_ip: str = "") -> tuple[str, str]:
    """전체 근거(evidence)의 raw 로그를 훑어 포트를 찾는다. 출발지 IP가 포함된 라인을 우선."""
    best = ("", "")
    for e in ev:
        if not isinstance(e, dict):
            continue
        raw = str(e.get("request_raw") or e.get("raw") or "")
        sp, dp = _ports_from_raw(raw, src_ip, dest_ip)
        if sp or dp:
            if src_ip and src_ip in raw:    # 출발지가 있는 라인 → 가장 신뢰, 즉시 채택
                return sp, dp
            if not (best[0] or best[1]):
                best = (sp, dp)
    return best


def _clean_param(s: Any) -> str:
    """'(IDS 본문 미캡처)' 같은 플레이스홀더는 빈 값으로 취급."""
    s = str(s or "").strip()
    return "" if (not s or s.startswith("(") or s in ("-", "None")) else s


def _best_param(rep: dict, ev: list, summary: dict) -> str:
    """근거(evidence)/요약에서 '실제 주입 파라미터·페이로드'를 찾는다.

    룰마다 키가 다르다: payload(WAF) / injected_params(앱·Mass Assignment) 등.
    플레이스홀더(IDS 본문 미캡처 등)는 건너뛰고 진짜 값을 우선한다.
    """
    p = _clean_param(rep.get("payload")) or _clean_param(rep.get("injected_params"))
    if p:
        return p
    for e in ev:
        if isinstance(e, dict):
            q = _clean_param(e.get("payload")) or _clean_param(e.get("injected_params"))
            if q:
                return q
    return _clean_param(summary.get("injected_params")) if isinstance(summary, dict) else ""


def _map_notable(d: dict[str, Any], t: Any) -> dict[str, Any]:
    """soc_notable_json의 상관탐지(JSON)를 분석플랫폼 알림 스키마로 매핑한다.

    - 기존 화면/판정과 호환되도록 signature·src_ip·severity 등을 채우고,
    - 대표 근거(evidence[0])의 페이로드를 uri/payload/body로 펼쳐 페이로드 기반 판정도 가능케 하며,
    - 상관 전용 필드(detection_class·rule_id·risk_score·evidence·summary)를 함께 싣는다.
    """
    ev = d.get("evidence") if isinstance(d.get("evidence"), list) else []
    rep = ev[0] if ev and isinstance(ev[0], dict) else {}
    summary = d.get("summary") if isinstance(d.get("summary"), dict) else {}
    entity = str(d.get("entity", "") or "")
    dest_ip = str(rep.get("dest_ip") or summary.get("targets") or summary.get("target") or "")
    # 출발지 vs 자산 구분: 근거/entity에 실제 IP가 있으면 공격 출발지(공격자),
    # 호스트명뿐이면(호스트형 탐지: 권한상승·C2·지속성 등) '영향 자산'으로 분리한다.
    attacker_ip = ""
    if _has_ip(rep.get("src_ip")):
        attacker_ip = _first_ip(rep.get("src_ip"))
    elif _has_ip(entity):
        attacker_ip = _first_ip(entity)
    if attacker_ip:
        src_ip, asset = attacker_ip, ""
    else:
        src_ip, asset = "", entity            # 외부 출발지 없음 → entity는 피해 자산(호스트)
    # 포트: evidence에 명시 필드가 있으면 사용, 없으면 raw 로그(Snort 'ip:port -> ip:port')에서 추출
    src_port = str(rep.get("src_port") or "").strip()
    dest_port = str(rep.get("dest_port") or "").strip()
    if not (src_port or dest_port):
        src_port, dest_port = _ports_from_evidence(ev, src_ip, dest_ip)
    title = d.get("rule_title") or d.get("rule_id") or "상관탐지"
    return {
        "_time": t,
        "Time": t,
        "signature": title,
        "rule_id": d.get("rule_id", ""),
        "rule_title": d.get("rule_title", ""),
        "mitre": d.get("mitre", ""),
        "source": "SIEM 상관룰",
        "source_type": "SIEM 상관룰",
        "severity": d.get("severity"),
        "risk_score": d.get("risk_score"),
        "risk_band": d.get("risk_band"),
        "event_count": d.get("event_count"),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "entity": entity,
        "asset": asset,                                       # 호스트형 탐지의 피해 자산(호스트명)
        "uri": str(rep.get("uri") or rep.get("url") or ""),    # uri/url(룰별 키 차이)
        "payload": _best_param(rep, ev, summary),              # 실제 주입 파라미터·페이로드
        "status": str(rep.get("status", "") or ""),
        "body": str(rep.get("request_raw") or rep.get("raw") or "")[:3000],  # request_raw/raw
        "detection_class": "correlation",
        "evidence": ev,                                        # 전체 기여 이벤트
        "evidence_count": d.get("evidence_count", len(ev)),
        "summary": summary,
    }


class SplunkClient:
    def __init__(self) -> None:
        self.base_url = f"https://{config.SPLUNK_HOST}:{config.SPLUNK_PORT}"
        self.session = requests.Session()
        self.session.verify = config.SPLUNK_VERIFY_SSL
        if config.SPLUNK_TOKEN:
            self.session.headers["Authorization"] = f"Bearer {config.SPLUNK_TOKEN}"
        else:
            self.session.auth = (config.SPLUNK_USERNAME, config.SPLUNK_PASSWORD)

    def search(
        self,
        spl: str,
        earliest: str = "-24h",
        latest: str = "now",
        timeout: int = 120,
    ) -> list[dict[str, Any]]:
        """블로킹 검색을 실행하고 결과 행 목록을 반환한다.

        spl 예: 'search index=ids sourcetype=snort severity>=2'
        """
        if config.SOC_MOCK:
            from mock_data import SAMPLE_ALERTS
            return list(SAMPLE_ALERTS)

        if not spl.strip().lower().startswith(("search", "|")):
            spl = f"search {spl}"

        sid = self._create_job(spl, earliest, latest)
        self._wait_until_done(sid, timeout)
        return self._fetch_results(sid)

    def _create_job(self, spl: str, earliest: str, latest: str) -> str:
        resp = self.session.post(
            f"{self.base_url}/services/search/jobs",
            data={
                "search": spl,
                "earliest_time": earliest,
                "latest_time": latest,
                "output_mode": "json",
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["sid"]

    def _wait_until_done(self, sid: str, timeout: int) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            resp = self.session.get(
                f"{self.base_url}/services/search/jobs/{sid}",
                params={"output_mode": "json"},
                timeout=30,
            )
            resp.raise_for_status()
            content = resp.json()["entry"][0]["content"]
            if content.get("isDone"):
                return
            time.sleep(1)
        raise TimeoutError(f"Splunk 검색 작업이 시간 내에 끝나지 않았습니다 (sid={sid})")

    def _fetch_results(self, sid: str) -> list[dict[str, Any]]:
        resp = self.session.get(
            f"{self.base_url}/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": 0},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json().get("results", [])

    def recent_alerts(
        self, index: str = "*", earliest: str = "-24h", latest: str = "now"
    ) -> list[dict[str, Any]]:
        """최근 알림/이벤트를 시간 역순으로 가져오는 헬퍼.

        config.ALERT_SOURCE="notable"(기본)면 SIEM 상관탐지(soc_notable_json)를,
        "socbase"면 단일 장비 alert(config.ALERT_SPL)를 가져온다.
        """
        if config.SOC_MOCK:
            from mock_data import SAMPLE_ALERTS
            return list(SAMPLE_ALERTS)

        if config.ALERT_SOURCE == "notable":
            return self.recent_notables(earliest=earliest, latest=latest)
        return self.search(config.ALERT_SPL, earliest=earliest, latest=latest)

    def recent_notables(
        self, earliest: str = "-24h", latest: str = "now", head: int | None = None
    ) -> list[dict[str, Any]]:
        """SIEM 상관탐지(soc_notable_json, _raw=JSON)를 받아 알림 스키마로 매핑해 반환.

        head를 주면 NOTABLE_SPL의 head 제한을 그 값으로 바꾼다(기록 탭의 전체 조회용).
        """
        spl = config.NOTABLE_SPL
        if head is not None:
            spl = re.sub(r"\|\s*head\s+\d+", f"| head {int(head)}", spl)
        rows = self.search(spl, earliest=earliest, latest=latest)
        out: list[dict[str, Any]] = []
        for r in rows:
            try:
                d = json.loads(r.get("_raw") or "")
            except Exception:
                continue                       # JSON 아닌(구형/table형) 이벤트는 건너뜀
            if isinstance(d, dict) and d.get("rule_id"):
                out.append(_map_notable(d, r.get("_time")))
        return out

    def alert_summary(
        self, earliest: str = "-24h", latest: str = "now"
    ) -> list[dict[str, Any]]:
        """금일 위협 현황용 집계 — head 100 제한 없이 24h 전체를
        (시그니처, 위험도)별 건수로 집계해 반환한다. [{signature, severity, count}, ...]
        """
        if config.SOC_MOCK:
            from mock_data import SAMPLE_ALERTS
            agg: dict[tuple[str, str], int] = {}
            for e in SAMPLE_ALERTS:
                key = (
                    e.get("signature") or e.get("sourcetype") or "event",
                    str(e.get("severity") if e.get("severity") is not None else 0),
                )
                agg[key] = agg.get(key, 0) + 1
            return [
                {"signature": s, "severity": sev, "count": c}
                for (s, sev), c in agg.items()
            ]

        spl = (
            r"`soc_base` "
            r"| fillnull value=0 severity "
            r"| stats count as count by signature severity"
        )
        return self.search(spl, earliest=earliest, latest=latest)

    def alert_geo(
        self, earliest: str = "-24h", latest: str = "now", limit: int = 150
    ) -> list[dict[str, Any]]:
        """지구본 호(arc)용 집계 — head 100 제한 없이 24h 전체를
        '출발지→목적지→시그니처' 흐름으로 묶는다. [{src_ip, dest_ip, signature, severity, count, src_count}]

        DDoS 등 대량성은 출발지가 분산(수천)이라 흐름이 폭증하므로 대상(dest)별로 합쳐
        src_ip='(분산)' 한 줄기로 만든다. 그 외는 출발지=공격자 기준 유지.
        건수 내림차순 상위 limit개만 반환해 호 개수를 제한한다.
        """
        if config.SOC_MOCK:
            from mock_data import SAMPLE_ALERTS
            agg: dict[tuple[str, str, str], dict[str, Any]] = {}
            for e in SAMPLE_ALERTS:
                sig = e.get("signature") or e.get("sourcetype") or "event"
                is_flood = bool(re.search(r"ddos|flood|denial", sig, re.I))
                src = "(분산)" if is_flood else (e.get("src_ip") or "?")
                key = (src, e.get("dest_ip") or "?", sig)
                g = agg.setdefault(key, {"src_ip": src, "dest_ip": e.get("dest_ip") or "?",
                                         "signature": sig, "severity": 0, "count": 0, "_srcs": set()})
                g["count"] += 1
                g["severity"] = max(g["severity"], int(e.get("severity") or 0))
                if e.get("src_ip"):
                    g["_srcs"].add(e["src_ip"])
            out = []
            for g in agg.values():
                g["src_count"] = len(g.pop("_srcs"))
                out.append(g)
            out.sort(key=lambda x: x["count"], reverse=True)
            return out[:limit]

        spl = (
            r"`soc_base` "
            r"| eval sevn=if(isnum(severity),severity,0) "
            r'| eval _flood=if(match(signature,"(?i)ddos|flood|denial"),1,0) '
            r'| eval gsrc=if(_flood==1,"(분산)",src_ip) '
            r"| stats count as count, max(sevn) as severity, dc(src_ip) as src_count "
            r"by gsrc dest_ip signature "
            r"| rename gsrc as src_ip "
            r"| sort - count "
            rf"| head {int(limit)}"
        )
        return self.search(spl, earliest=earliest, latest=latest)


splunk_client = SplunkClient()
