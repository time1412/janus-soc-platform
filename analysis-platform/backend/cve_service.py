"""NVD(국가 취약점 데이터베이스) CVE 조회 서비스.

- 최근 30일 고위험(CVSS >= 7.0) CVE 피드
- 탐지된 공격 시그니처와 연관된 CVE 매핑
- SQLite TTL 캐시 (기본 6시간) — NVD 요청 제한 방어
"""
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Any

import requests

import config

# NVD API 키(있으면 50req/30s, 없으면 5req/30s). 환경변수로만 주입.
_NVD_API_KEY = getattr(config, "NVD_API_KEY", "") or os.getenv("NVD_API_KEY", "")

_SESSION = requests.Session()
_SESSION.headers["User-Agent"] = "SOC-Platform/0.1"

CVE_CACHE_DB = config.BASE_DIR / "storage" / "cve_cache.db"
CVE_CACHE_TTL_HOURS = 6

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 탐지 시그니처(상관룰 한글 제목 포함) → NVD keywordSearch 키워드 매핑.
# 정확 일치가 아니라 '부분일치'로 공격 유형을 추론한다(예: "SQLi 차단실패·성공 의심" → sql injection).
# 순서 중요: 더 구체적인 규칙을 위에 둔다. NVD keywordSearch는 단어 AND이므로 키워드는 짧게.
_KEYWORD_RULES: list[tuple[tuple[str, ...], str]] = [
    (("sqli", "sql injection", "sql 인젝션", "sql주입", "인젝션"), "sql injection"),
    (("rce", "remote code", "원격 코드", "명령실행", "명령 실행", "코드 실행"), "remote code execution"),
    (("웹쉘", "웹셸", "webshell", "web shell"), "web shell"),
    (("경로순회", "path travers", "directory travers", "디렉터리 순회", "lfi", "rfi",
      "file inclusion", "파일 유출"), "path traversal"),
    (("리버스셸", "reverse shell", "백도어", "backdoor", "implant", "c2 "), "backdoor"),
    (("xss", "cross-site script", "크로스사이트", "스크립트 삽입", "세션쿠키", "쿠키 탈취",
      "캠페인"), "cross-site scripting"),
    (("역직렬화", "deserial"), "deserialization"),
    (("ssrf",), "server-side request forgery"),
    (("xxe", "xml external"), "xml external entity"),
    (("ssti", "template injection", "템플릿"), "template injection"),
    (("csrf", "요청 위조", "요청위조"), "cross-site request forgery"),
    (("업로드", "upload"), "file upload"),
    (("스터핑", "credential stuffing", "계정탈취", "브루트", "brute"), "credential stuffing"),
    (("랜섬", "ransom"), "ransomware"),
    (("권한상승", "권한 상승", "privesc", "privilege"), "privilege escalation"),
    (("인가우회", "인증 우회", "권한 우회", "권한파라미터", "mass assignment"), "access control"),
    (("ddos", "디도스", "가용성", "denial", "flood", "l7 dos"), "denial of service"),
    (("민감", "자격파일", "설정 노출", "정보 노출", "노출"), "information disclosure"),
    (("복합 웹", "웹공격", "web attack", "킬체인"), "web application"),
]


def _keyword_for(sig: str) -> str | None:
    """시그니처에서 공격 유형을 추론해 NVD 키워드를 반환(없으면 None)."""
    s = (sig or "").lower()
    for pats, kw in _KEYWORD_RULES:
        if any(p in s for p in pats):
            return kw
    return None

_CVSS_COLOR = {
    "CRITICAL": "#dc4e41",
    "HIGH":     "#f8be34",
    "MEDIUM":   "#2e6ca4",
    "LOW":      "#53a051",
}


class CveService:
    def __init__(self) -> None:
        self._init_cache()

    def _init_cache(self) -> None:
        CVE_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(CVE_CACHE_DB) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_cache (
                    cache_key TEXT PRIMARY KEY,
                    data      TEXT NOT NULL,
                    cached_at TEXT NOT NULL
                )
            """)

    def _nvd_get(self, params: dict) -> dict:
        """NVD 요청 + 503/429 재시도(백오프). 미인증은 스로틀링이 잦아 재시도 필수."""
        headers = {"apiKey": _NVD_API_KEY} if _NVD_API_KEY else {}
        last = ""
        for attempt in range(4):
            try:
                resp = _SESSION.get(NVD_BASE, params=params, headers=headers, timeout=25)
                if resp.status_code in (429, 503):
                    last = f"{resp.status_code} {resp.reason}"
                    time.sleep(4 * (attempt + 1))    # 4s, 8s, 12s …
                    continue
                resp.raise_for_status()
                return resp.json()
            except requests.RequestException as exc:
                last = str(exc)
                time.sleep(2 * (attempt + 1))
        raise RuntimeError(f"NVD 조회 실패(재시도 초과): {last}")

    # ------------------------------------------------------------------ #
    # 공개 API
    # ------------------------------------------------------------------ #

    def get_recent_cves(self, limit: int = 8) -> list[dict[str, Any]]:
        """최근 30일 내 CVSS 7.0 이상 CVE를 최신순으로 반환한다."""
        key = f"recent_{limit}"
        cached = self._get_cache(key)
        if cached is not None:
            return cached

        now = datetime.utcnow()
        start = (now - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000")
        end = now.strftime("%Y-%m-%dT23:59:59.999")

        try:
            data = self._nvd_get({
                "pubStartDate": start,
                "pubEndDate":   end,
                "resultsPerPage": 20,
                "startIndex": 0,
            })
            items = self._parse_nvd(data)
            # CVSS 7.0 이상만 필터 후 점수 내림차순 상위 limit개
            items = sorted(
                [i for i in items if (i.get("score") or 0) >= 7.0],
                key=lambda x: x.get("score") or 0,
                reverse=True,
            )[:limit]
        except Exception as exc:
            return [{"error": str(exc)}]

        self._set_cache(key, items)
        return items

    def get_cves_for_signatures(
        self, signatures: list[str]
    ) -> dict[str, list[dict[str, Any]]]:
        """탐지된 시그니처별로 관련 CVE(상위 5건)를 반환한다.

        시그니처에서 공격 유형을 부분일치로 추론(_keyword_for)하고, 키워드 1개당
        NVD를 1회만 조회해(중복 키워드 캐시) 같은 키워드의 모든 시그니처에 매핑한다.
        """
        result: dict[str, list] = {}
        kw_results: dict[str, list] = {}     # keyword → CVE 목록(이번 호출 캐시)

        for sig in signatures:
            keyword = _keyword_for(sig)
            if not keyword:
                continue
            if keyword not in kw_results:
                kw_results[keyword] = self._cves_for_keyword(keyword)
            result[sig] = kw_results[keyword]

        return result

    def _cves_for_keyword(self, keyword: str) -> list[dict[str, Any]]:
        """NVD에서 키워드 관련 고위험 CVE 상위 5건(캐시 6h)."""
        key = f"sig_{keyword.replace(' ', '_')}"
        cached = self._get_cache(key)
        if cached is not None:
            return cached
        try:
            data = self._nvd_get(
                {"keywordSearch": keyword, "resultsPerPage": 30, "startIndex": 0})
            items = self._parse_nvd(data)
            items = sorted(
                [i for i in items if (i.get("score") or 0) >= 7.0],
                key=lambda x: x.get("score") or 0,
                reverse=True,
            )[:5]
        except Exception as exc:
            items = [{"error": str(exc)}]
        # 성공한 결과만 6h 캐시(에러는 캐시 안 함 → 다음에 재시도)
        if items and not items[0].get("error"):
            self._set_cache(key, items)
        time.sleep(1.5)  # 키워드 간 간격(미인증 스로틀 완화)
        return items

    # ------------------------------------------------------------------ #
    # NVD 응답 파싱
    # ------------------------------------------------------------------ #

    def _parse_nvd(self, data: dict) -> list[dict[str, Any]]:
        out = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")

            desc_en = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "",
            )

            score, severity = None, None
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(metric_key, [])
                if metrics:
                    cd = metrics[0].get("cvssData", {})
                    score = cd.get("baseScore")
                    severity = cd.get("baseSeverity") or cd.get("baseSeverityV2")
                    break

            out.append({
                "id":          cve_id,
                "description": desc_en[:220] + ("…" if len(desc_en) > 220 else ""),
                "score":       score,
                "severity":    severity,
                "color":       _CVSS_COLOR.get(str(severity).upper(), "#6c757d"),
                "published":   cve.get("published", "")[:10],
                "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return out

    # ------------------------------------------------------------------ #
    # SQLite 캐시
    # ------------------------------------------------------------------ #

    def _get_cache(self, key: str) -> list | None:
        with sqlite3.connect(CVE_CACHE_DB) as conn:
            row = conn.execute(
                "SELECT data, cached_at FROM cve_cache WHERE cache_key = ?", (key,)
            ).fetchone()
        if not row:
            return None
        age = datetime.now() - datetime.fromisoformat(row[1])
        if age > timedelta(hours=CVE_CACHE_TTL_HOURS):
            return None
        return json.loads(row[0])

    def _set_cache(self, key: str, data: list) -> None:
        with sqlite3.connect(CVE_CACHE_DB) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cve_cache (cache_key, data, cached_at) VALUES (?, ?, ?)",
                (key, json.dumps(data, ensure_ascii=False), datetime.now().isoformat()),
            )


cve_service = CveService()
