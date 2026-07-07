"""로컬 데모용 목(mock) 데이터.

config.SOC_MOCK=true 일 때 splunk_client / gemini_service 가 이 데이터를 사용한다.
망 구성도(공격자 10.44.44.44, 웹서비스 10.0.10.100, DB 10.0.200.100 등)에 맞춰
실제와 유사한 보안 이벤트를 흉내낸다. 출발지에는 지구본 시각화를 위한 좌표를 넣었다.
"""
from datetime import datetime, timedelta


def _t(minutes_ago: int) -> str:
    return (datetime.now() - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S")


SAMPLE_ALERTS = [
    {
        "_time": _t(2), "host": "WAF", "source": "waf:access", "sourcetype": "waf",
        "signature": "SQL Injection Attempt (UNION SELECT)", "src_ip": "203.0.113.45",
        "dest_ip": "10.0.10.100", "severity": 3,
        "src_lat": 39.9042, "src_lon": 116.4074,  # 베이징
        "dest_lat": 37.5665, "dest_lon": 126.9780,
    },
    {
        "_time": _t(5), "host": "IDS", "source": "snort", "sourcetype": "snort",
        "signature": "Web Shell Upload Detected (cmd.jsp)", "src_ip": "91.219.236.18",
        "dest_ip": "10.0.10.100", "severity": 3,
        "src_lat": 55.7558, "src_lon": 37.6173,  # 모스크바
        "dest_lat": 37.5665, "dest_lon": 126.9780,
    },
    {
        "_time": _t(8), "host": "IDS", "source": "snort", "sourcetype": "snort",
        "signature": "SSH Brute Force (multiple failed logins)", "src_ip": "198.51.100.23",
        "dest_ip": "10.0.200.100", "severity": 2,
        "src_lat": 52.5200, "src_lon": 13.4050,  # 베를린
        "dest_lat": 37.5665, "dest_lon": 126.9780,
    },
    {
        "_time": _t(12), "host": "WAF", "source": "waf:access", "sourcetype": "waf",
        "signature": "Reflected XSS Attempt", "src_ip": "45.83.122.10",
        "dest_ip": "10.0.10.100", "severity": 2,
        "src_lat": 48.8566, "src_lon": 2.3522,  # 파리
        "dest_lat": 37.5665, "dest_lon": 126.9780,
    },
    {
        "_time": _t(15), "host": "IPS", "source": "ips", "sourcetype": "ips",
        "signature": "Port Scan (TCP SYN sweep)", "src_ip": "185.220.101.5",
        "dest_ip": "10.0.10.100", "severity": 1,
        "src_lat": 40.7128, "src_lon": -74.0060,  # 뉴욕
        "dest_lat": 37.5665, "dest_lon": 126.9780,
    },
    {
        "_time": _t(20), "host": "IDS", "source": "snort", "sourcetype": "snort",
        "signature": "Malware C2 Beacon (DNS tunneling)", "src_ip": "10.0.150.12",
        "dest_ip": "104.21.55.18", "severity": 3,
        "src_lat": 37.5665, "src_lon": 126.9780,  # 내부 감염 PC -> 외부 C2
        "dest_lat": -33.8688, "dest_lon": 151.2093,  # 시드니
    },
    {
        "_time": _t(26), "host": "IPS", "source": "ips", "sourcetype": "ips",
        "signature": "RDP Brute Force", "src_ip": "159.65.200.77",
        "dest_ip": "10.0.150.10", "severity": 2,
        "src_lat": 1.3521, "src_lon": 103.8198,  # 싱가포르
        "dest_lat": 37.5665, "dest_lon": 126.9780,
    },
    {
        "_time": _t(33), "host": "WAF", "source": "waf:access", "sourcetype": "waf",
        "signature": "Path Traversal (../../etc/passwd)", "src_ip": "77.88.55.66",
        "dest_ip": "10.0.10.100", "severity": 3,
        "src_lat": 51.5074, "src_lon": -0.1278,  # 런던
        "dest_lat": 37.5665, "dest_lon": 126.9780,
    },
]


def mock_chat_answer(question: str, events: list[dict]) -> str:
    """Gemini 호출 없이 만드는 데모용 챗봇 답변 (간단한 통계 기반)."""
    from collections import Counter

    if not events:
        return "수집된 로그가 없어 답변할 수 없습니다."

    sev_count = Counter(str(e.get("severity", "?")) for e in events)
    sig_count = Counter(str(e.get("signature", "?")) for e in events)
    src_count = Counter(str(e.get("src_ip", "?")) for e in events)
    top_sig = sig_count.most_common(3)
    top_src = src_count.most_common(3)

    return (
        f"[데모 답변 — 목 모드] 질문: \"{question}\"\n\n"
        f"수집된 로그 {len(events)}건 기준으로 답변드립니다.\n"
        f"- 위험도 분포: " + ", ".join(f"{k}={v}건" for k, v in sorted(sev_count.items())) + "\n"
        f"- 주요 시그니처: " + ", ".join(f"{k}({v})" for k, v in top_sig) + "\n"
        f"- 상위 출발지 IP: " + ", ".join(f"{k}({v})" for k, v in top_src) + "\n\n"
        "실제 GEMINI_API_KEY를 설정하면 이 질문에 대한 맥락 기반 자연어 답변이 제공됩니다."
    )


def mock_ti_lookup(ip: str) -> dict:
    """Gemini/AbuseIPDB 없이 반환하는 데모용 IP 평판 데이터."""
    import ipaddress
    try:
        if ipaddress.ip_address(ip).is_private:
            return {"ip": ip, "risk_score": 0, "is_malicious": False, "sources": {}}
    except ValueError:
        pass

    _DB = {
        "203.0.113.45":  {"confidence_score": 97,  "total_reports": 342,  "country_code": "CN", "isp": "ChinaNet",          "last_reported": "2026-05-27T14:22:00+00:00", "usage_type": "Data Center/Web Hosting/Transit"},
        "91.219.236.18": {"confidence_score": 89,  "total_reports": 178,  "country_code": "RU", "isp": "PE Ivanov",         "last_reported": "2026-05-26T09:11:00+00:00", "usage_type": "Data Center/Web Hosting/Transit"},
        "198.51.100.23": {"confidence_score": 65,  "total_reports": 43,   "country_code": "DE", "isp": "Hetzner Online",    "last_reported": "2026-05-25T03:45:00+00:00", "usage_type": "Data Center/Web Hosting/Transit"},
        "45.83.122.10":  {"confidence_score": 72,  "total_reports": 91,   "country_code": "FR", "isp": "OVH SAS",           "last_reported": "2026-05-27T01:00:00+00:00", "usage_type": "Data Center/Web Hosting/Transit"},
        "185.220.101.5": {"confidence_score": 100, "total_reports": 1247, "country_code": "US", "isp": "Tor Exit Node",     "last_reported": "2026-05-27T15:00:00+00:00", "usage_type": "Tor Exit Node"},
        "159.65.200.77": {"confidence_score": 81,  "total_reports": 220,  "country_code": "SG", "isp": "DigitalOcean",      "last_reported": "2026-05-27T10:30:00+00:00", "usage_type": "Data Center/Web Hosting/Transit"},
        "77.88.55.66":   {"confidence_score": 55,  "total_reports": 67,   "country_code": "GB", "isp": "Yandex LLC",        "last_reported": "2026-05-24T20:00:00+00:00", "usage_type": "Search Engine Spider"},
        "104.21.55.18":  {"confidence_score": 78,  "total_reports": 156,  "country_code": "US", "isp": "Cloudflare (C2)",   "last_reported": "2026-05-27T12:00:00+00:00", "usage_type": "Content Delivery Network"},
    }
    adb = _DB.get(ip, {"confidence_score": 0, "total_reports": 0, "country_code": "??", "isp": "Unknown", "last_reported": "", "usage_type": "Unknown"})
    score = adb["confidence_score"]
    otx = {
        "pulse_count": max(0, score // 20),
        "pulse_names": ["APT Campaign 2026", "Mass Scanner Botnet"] if score > 70 else [],
        "reputation": -score,
        "country_code": adb["country_code"],
    }
    risk = max(score, min(50 + otx["pulse_count"] * 5, 100) if otx["pulse_count"] else 0)
    return {
        "ip": ip,
        "risk_score": risk,
        "is_malicious": risk >= 50,
        "sources": {"abuseipdb": adb, "otx": otx},
    }


def mock_trends(days: int = 7) -> dict:
    """InsightsService.get_trends()의 데모 응답."""
    return {
        "period_days": days,
        "stats": {
            "total": 3421,
            "by_signature": [
                {"signature": "SQL Injection Attempt (UNION SELECT)", "count": "1204"},
                {"signature": "Port Scan (TCP SYN sweep)",             "count": "847"},
                {"signature": "SSH Brute Force (multiple failed logins)", "count": "612"},
                {"signature": "Web Shell Upload Detected (cmd.jsp)",   "count": "341"},
                {"signature": "Reflected XSS Attempt",                 "count": "218"},
                {"signature": "Path Traversal (../../etc/passwd)",     "count": "112"},
                {"signature": "RDP Brute Force",                       "count": "87"},
            ],
            "by_severity": [
                {"severity": "3", "count": "1657"},
                {"severity": "2", "count": "1251"},
                {"severity": "1", "count": "513"},
            ],
            "daily_trend": [
                {"_time": "2026-05-21", "count": "389"},
                {"_time": "2026-05-22", "count": "421"},
                {"_time": "2026-05-23", "count": "478"},
                {"_time": "2026-05-24", "count": "512"},
                {"_time": "2026-05-25", "count": "590"},
                {"_time": "2026-05-26", "count": "643"},
                {"_time": "2026-05-27", "count": "388"},
            ],
        },
        "interpretation": (
            "[데모] 위협 트렌드 분석\n\n"
            "1. SQL Injection(1,204건)이 전체 공격의 35%를 차지하며 가장 빈번한 위협입니다. "
            "전주 대비 278% 증가 추세로 자동화 스캔 공격 도구 사용이 의심됩니다.(추정)\n\n"
            "2. 포트스캔(847건)·SSH 브루트포스(612건)가 동시 증가 중이며, "
            "공격자가 취약 서비스 탐색 후 침투를 시도하는 단계적 패턴으로 보입니다.(추정)\n\n"
            "3. 웹쉘 업로드 시도(341건)는 실제 침투 성공 시 서버 완전 장악으로 이어질 수 있어 "
            "가장 시급한 위협입니다.\n\n"
            "즉시 확인: 웹서버 디렉토리 내 .jsp/.php 이상 파일 존재 여부 점검 권고."
        ),
    }


def mock_summary() -> dict:
    """InsightsService.get_summary()의 데모 응답."""
    from datetime import datetime
    return {
        "generated_at": datetime.now().isoformat(),
        "summary": (
            "[데모] 주간 위협 요약 — 2026년 5월 4주차\n\n"
            "이번 주 총 3,421건의 보안 이벤트가 탐지되어 전주 대비 12% 증가하였으며, "
            "고위험(severity 3) 이벤트 비율이 48%로 전주(38%) 대비 크게 상승하였습니다.\n\n"
            "주요 위협:\n"
            "• SQL Injection(SQL 삽입 공격) 1,204건 — 전주 대비 278% 급증, 자동화 공격 도구 사용 추정\n"
            "• 웹쉘(Web Shell, 원격 명령 실행 악성 파일) 업로드 341건 — 성공 시 서버 완전 장악 가능\n"
            "• 내부 PC(10.0.150.12) C2(명령·제어 서버) 비콘 탐지 — 악성코드 감염 후 외부 통신 시도\n\n"
            "권고 조치:\n"
            "• 웹서버(10.0.10.100) 내 비인가 스크립트 파일 즉시 점검 및 삭제\n"
            "• 내부 감염 의심 PC 네트워크 격리 및 포렌식 조사 의뢰\n"
            "• SQL Injection 상위 출발지 IP 방화벽 차단 (AbuseIPDB 신뢰도 80 이상 기준)"
        ),
    }


def mock_analysis(events: list[dict]) -> str:
    """Gemini 호출 없이 만드는 데모용 분석 보고서 텍스트."""
    if not events:
        return "분석할 이벤트가 없습니다."
    top = max(events, key=lambda e: e.get("severity", 0))
    src_ips = ", ".join(sorted({str(e.get("src_ip", "?")) for e in events}))
    dst_ips = ", ".join(sorted({str(e.get("dest_ip", "?")) for e in events}))
    return f"""[데모 분석 — 목 모드]

1. 사건 요약
탐지된 보안 이벤트 {len(events)}건을 분석했습니다. 가장 위험도가 높은 이벤트는
'{top.get('signature')}' (위험도 {top.get('severity')}) 로, {top.get('src_ip')} 에서
{top.get('dest_ip')} 로 향한 공격입니다.

2. 공격 유형 분류
- 웹 공격(SQL Injection / XSS / Path Traversal) → MITRE ATT&CK T1190 (Exploit Public-Facing App)
- 인증 공격(SSH/RDP Brute Force) → T1110 (Brute Force)
- 악성코드 통신(C2 Beacon) → T1071 (Application Layer Protocol)

3. 위험도 평가: 높음
공개 웹서비스(10.0.10.100)에 대한 다수의 익스플로잇 시도와 내부 PC의 C2 통신 정황이
동시에 관측되어 침해 가능성이 높습니다. (추정)

4. 영향받은 자산 및 IP
- 출발지: {src_ips}
- 목적지: {dst_ips}

5. 즉시 조치사항
1) 웹서비스(10.0.10.100) 접근 로그 보존 및 웹쉘 존재 여부 점검
2) 내부 감염 의심 PC(10.0.150.12) 네트워크 격리
3) 공격 출발지 IP 방화벽 차단
4) DB(10.0.200.100) 계정 비밀번호 강제 변경

6. 재발 방지 권고
- WAF 시그니처 업데이트 및 가상 패치 적용
- 외부 노출 서비스의 SSH/RDP 인증 강화(키 기반/MFA)
- 내부망 아웃바운드 트래픽 모니터링 강화
"""
