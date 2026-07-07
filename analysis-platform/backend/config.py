"""환경 설정 로더 — .env 파일에서 값을 읽어 모듈 전역으로 제공한다."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# --- Splunk (인트라넷 10.0.200.0/24) ---
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "10.0.200.201")   # ESM
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))      # 관리(REST) 포트
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")             # 토큰 인증 시 사용 (우선)
SPLUNK_VERIFY_SSL = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"

# --- Gemini AI ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# --- 소통플랫폼 연동 (정탐 이벤트 전달 대상) ---
COMM_PLATFORM_URL = os.getenv("COMM_PLATFORM_URL", "http://localhost:8810")
COMM_FORWARD_ENABLED = os.getenv("COMM_FORWARD_ENABLED", "true").lower() == "true"

# --- 사이버 위기 경보단계 (KrCERT 실시간 파싱; 조회 실패/폐쇄망 시 폴백 표시값) ---
CRISIS_LEVEL_FALLBACK = os.getenv("CRISIS_LEVEL_FALLBACK", "관심")

# --- 정·오탐 머지(상관) 시간 윈도우 ---
# 같은 (공격유형+출발지IP)라도 이 시간 윈도우를 벗어나면 새 인시던트로 본다.
# 멀티센서·GET/POST 등 동일 사건의 분산 탐지는 묶되, 새 시점의 공격은 분리.
TRIAGE_MERGE_WINDOW_MIN = int(os.getenv("TRIAGE_MERGE_WINDOW_MIN", "30"))
TRIAGE_MERGE_WINDOW_SEC = TRIAGE_MERGE_WINDOW_MIN * 60

# 상관탐지(SIEM notable) 전용 중복제거 창(초). 같은 룰·출발지라도 이 창을 벗어나면 새 티켓.
# 기존 86400(하루 1티켓) → 60(1분당 1티켓). 지속 공격 시 티켓·LLM 판정이 분 단위로 증가함.
TRIAGE_CORR_WINDOW_SEC = int(os.getenv("TRIAGE_CORR_WINDOW_SEC", "60"))

# --- 볼륨(대량성) 정탐 보정 임계치 ---
# DDoS 등 페이로드가 없는 '양/속도' 기반 공격은 내용 기반 LLM이 오탐으로 보기 쉽다.
# 단일 대상에 묶인 건수(merged_count) 또는 분산 출발지 수(merged_src_count)가
# 이 임계치 이상이면 페이로드와 무관하게 정탐(DDoS)으로 확정한다.
TRIAGE_FLOOD_MIN = int(os.getenv("TRIAGE_FLOOD_MIN", "20"))

# --- 파라미터 공격(SQLi/XSS 등) 페이로드별 분리 ---
# True면 같은 출발지·유형·시간이라도 '페이로드 구조'가 다르면 별도 인시던트(=티켓)로 분리한다.
# (숫자 리터럴만 다른 난사 변형 id=1/id=2 등은 같은 것으로 보아 폭주를 막음. DDoS 등 대량성은 영향 없음.)
TRIAGE_SPLIT_BY_PAYLOAD = os.getenv("TRIAGE_SPLIT_BY_PAYLOAD", "true").lower() == "true"

# --- Threat Intelligence ---
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
TI_CACHE_TTL_HOURS = int(os.getenv("TI_CACHE_TTL_HOURS", "24"))
TI_CACHE_DB = BASE_DIR / "storage" / "ti_cache.db"

# --- 데모/목 모드 (실제 Splunk·Gemini 없이 샘플 데이터로 동작) ---
SOC_MOCK = os.getenv("SOC_MOCK", "false").lower() == "true"

# --- 대시보드 알림 검색 쿼리 ---
# SOC_ALERT_SPL 환경변수로 덮어쓸 수 있다.
# 스플렁크 대시보드(soc_security_dashboard)의 '보안 이벤트 목록'과 동일 소스를 사용한다.
#   soc_base 매크로 = WAF Web(modsec) + IDS/OSSEC(sguil) + pfSense(filterlog/Snort) 통합·정규화
#   (source_type, signature, severity, src_ip/port, dest_ip/port, uri, status 표준화 + 내부망 IP 제외)
# 여기에 WAF POST 본문(modsec C 섹션) 추출만 덧붙여 정·오탐 판정 품질을 높인다.
_DEFAULT_ALERT_SPL = (
    r'`soc_base` '
    # POST 본문(modsec audit C 섹션) 추출 — POST 공격 payload는 URI가 아닌 본문에 있음
    r'| rex field=_raw "-{2,}\w+-{2,}C-{2,}(?<body>[\s\S]*?)-{2,}\w+-{2,}[A-Z]-{2,}" '
    r'| eval body=trim(replace(body,"[\r\n]+"," ")) '
    r'| eval source=source_type '   # 코드 호환: triage/프론트가 source 필드 사용
    r'| table _time, host, source, source_type, signature, src_ip, src_port, dest_ip, dest_port, severity, uri, status, body '
    r'| sort -_time | head 100'
)
ALERT_SPL = os.getenv("SOC_ALERT_SPL", _DEFAULT_ALERT_SPL)

# | table / | sort 제거한 집계 전용 베이스 — insights_service가 stats를 뒤에 붙여 사용
import re as _re
ALERT_BASE_SPL = _re.sub(r"\|\s*table\b.*", "", ALERT_SPL, flags=_re.DOTALL | _re.IGNORECASE).strip()

# --- SIEM 상관(notable) 수신 ---
# 상관룰 결과는 soc_notable_json(_raw=JSON)에 적재된다. sourcetype 필터로 JSON 룰만 받는다
# (CORR-005/006 등 table형 collect는 sourcetype이 달라 자동 제외).
NOTABLE_SPL = os.getenv(
    "SOC_NOTABLE_SPL",
    'search index=soc_notable_json sourcetype="soc:notable:json" '
    "| sort -_time | head 100 | fields _raw _time",
)
# 분석플랫폼 1차 알림 소스: "notable"(상관탐지) | "socbase"(단일 장비 alert).
# 인사이트(insights_service)는 ALERT_BASE_SPL(soc_base 원시 집계)을 그대로 사용한다.
ALERT_SOURCE = os.getenv("SOC_ALERT_SOURCE", "notable").lower()

# --- 저장소 ---
PDF_OUTPUT_DIR = BASE_DIR / "storage" / "pdf_reports"
PDF_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --- 서버 ---
APP_HOST = os.getenv("APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("APP_PORT", "8800"))  # 8000은 Splunk Web이 사용
