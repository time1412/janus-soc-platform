"""외부 Threat Intelligence API 조회 및 SQLite 캐시 관리.

AbuseIPDB, AlienVault OTX를 이용해 IP 평판을 조회하고,
결과를 SQLite에 TTL 기반으로 캐싱한다.
"""
import ipaddress
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Any

import requests

import config

_SESSION = requests.Session()
_SESSION.headers["Accept"] = "application/json"


class ThreatIntelService:
    def __init__(self) -> None:
        self._init_cache()

    def _init_cache(self) -> None:
        config.TI_CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(config.TI_CACHE_DB) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ti_cache (
                    ip      TEXT PRIMARY KEY,
                    data    TEXT NOT NULL,
                    cached_at TEXT NOT NULL
                )
            """)

    # ------------------------------------------------------------------ #
    # 공개 API
    # ------------------------------------------------------------------ #

    def lookup_ip(self, ip: str) -> dict[str, Any]:
        """단일 IP 위협 인텔리전스 조회 (캐시 우선)."""
        if config.SOC_MOCK:
            from mock_data import mock_ti_lookup
            return mock_ti_lookup(ip)

        cached = self._get_cache(ip)
        if cached is not None:
            return cached

        result = self._fetch(ip)
        self._set_cache(ip, result)
        return result

    def enrich_events(self, events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        """이벤트 목록에서 외부 IP를 추출해 일괄 조회한다."""
        ips: set[str] = set()
        for e in events:
            for field in ("src_ip", "dest_ip"):
                ip = e.get(field, "")
                if ip and not _is_private(ip):
                    ips.add(ip)
        return {ip: self.lookup_ip(ip) for ip in ips}

    # ------------------------------------------------------------------ #
    # 내부 조회 로직
    # ------------------------------------------------------------------ #

    def _fetch(self, ip: str) -> dict[str, Any]:
        sources: dict[str, Any] = {}

        if config.ABUSEIPDB_API_KEY:
            sources["abuseipdb"] = self._abuseipdb(ip)

        if config.OTX_API_KEY:
            sources["otx"] = self._otx(ip)

        risk = _calc_risk(sources)
        return {
            "ip": ip,
            "risk_score": risk,
            "is_malicious": risk >= 50,
            "sources": sources,
        }

    def _abuseipdb(self, ip: str) -> dict[str, Any]:
        try:
            resp = _SESSION.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": config.ABUSEIPDB_API_KEY},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            resp.raise_for_status()
            d = resp.json()["data"]
            return {
                "confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country_code": d.get("countryCode", ""),
                "isp": d.get("isp", ""),
                "last_reported": d.get("lastReportedAt", ""),
                "usage_type": d.get("usageType", ""),
            }
        except Exception as exc:
            return {"error": str(exc)}

    def _otx(self, ip: str) -> dict[str, Any]:
        try:
            resp = _SESSION.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": config.OTX_API_KEY},
                timeout=10,
            )
            resp.raise_for_status()
            d = resp.json()
            pulse_info = d.get("pulse_info", {})
            return {
                "pulse_count": pulse_info.get("count", 0),
                "pulse_names": [p["name"] for p in pulse_info.get("pulses", [])[:3]],
                "reputation": d.get("reputation", 0),
                "country_code": d.get("country_code", ""),
            }
        except Exception as exc:
            return {"error": str(exc)}

    # ------------------------------------------------------------------ #
    # SQLite 캐시
    # ------------------------------------------------------------------ #

    def _get_cache(self, ip: str) -> dict[str, Any] | None:
        with sqlite3.connect(config.TI_CACHE_DB) as conn:
            row = conn.execute(
                "SELECT data, cached_at FROM ti_cache WHERE ip = ?", (ip,)
            ).fetchone()
        if not row:
            return None
        age = datetime.now() - datetime.fromisoformat(row[1])
        if age > timedelta(hours=config.TI_CACHE_TTL_HOURS):
            return None
        return json.loads(row[0])

    def _set_cache(self, ip: str, data: dict[str, Any]) -> None:
        with sqlite3.connect(config.TI_CACHE_DB) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ti_cache (ip, data, cached_at) VALUES (?, ?, ?)",
                (ip, json.dumps(data, ensure_ascii=False), datetime.now().isoformat()),
            )


# ------------------------------------------------------------------ #
# 헬퍼
# ------------------------------------------------------------------ #

def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _calc_risk(sources: dict[str, Any]) -> int:
    score = 0
    if adb := sources.get("abuseipdb"):
        score = max(score, adb.get("confidence_score", 0))
    if otx := sources.get("otx"):
        pulses = otx.get("pulse_count", 0)
        if pulses > 0:
            score = max(score, min(50 + pulses * 5, 100))
    return score


threat_intel_service = ThreatIntelService()
