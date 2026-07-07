"""AI 정/오탐(true/false positive) 판별 서비스 — 분석플랫폼.

경보가 분석플랫폼에 들어오면 자동으로 정탐/오탐을 판정한다(백그라운드 + 캐시).
판정에는 신뢰도(confidence)와 그 신뢰도가 나온 이유(confidence_reason)가 포함된다.
정탐만 소통플랫폼으로 전달하고, 분석플랫폼 "정·오탐" 탭에서 결과를 조회한다.

OpenRouter(OpenAI 호환) API 사용. temperature 0(재현성).
"""
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

import requests

import config

try:                       # 모델이 만든 깨진 JSON 복구용(없으면 graceful 폴백)
    import json_repair as _json_repair
except Exception:          # noqa: BLE001
    _json_repair = None

_OR_URL = "https://openrouter.ai/api/v1/chat/completions"
_CACHE_FILE = config.BASE_DIR / "storage" / "triage_cache.json"

# 판별 기준(공통)
_CRITERIA = """[판별 기준]
- 정탐(true_positive): 페이로드/URI에 실제 공격 의도가 명확히 드러남.
  · SQL Injection: ' OR 1=1, UNION SELECT, CTXSYS.DRITHSX, 주석(-- #) 등 SQL 구문
  · XSS: <script>, onerror=, <img src=x>, document.cookie 탈취 등
  · Path Traversal: ../../../etc/passwd, ..%2f 등 상위 경로 탐색
  · Command Injection: ;ls, |cat, $(...), &&whoami 등 OS 명령 결합
  · Brute Force: 동일 출발지에서 인증 엔드포인트(/login 등)로 짧은 간격 반복 시도
  · 그 외(SSRF·XXE·SSTI·역직렬화·LDAP/NoSQL Injection·파일 업로드·오픈 리다이렉트 등)도
    목록에 없더라도 페이로드에 공격 의도가 보이면 정탐으로 판정하고 attack_type에 명시한다.
- 오탐(false_positive): 시그니처는 매칭됐으나 정상 트래픽일 가능성이 높음.
  · 정상 검색어/파라미터 (예: keyword=bts, keyword=콘서트)
  · 세션 식별자 (예: ;jsessionid=ABC123 — 'id'가 명령어가 아님)
  · 정상적인 파일 경로/확장자, 정상 로그인 1~2회
  · 내부 점검/인증된 스캐너로 보이는 트래픽

[판별 원칙]
1. 반드시 페이로드(URI/본문)의 '실제 내용'을 근거로 판단한다. 시그니처 이름만 믿지 않는다.
2. URL 인코딩은 디코딩된 값으로 해석한다 (%27 → ' , %3C → < ).
3. 목록에 없는 공격 유형도 일반 원칙으로 판정한다(예시는 화이트리스트가 아님).
4. 애매하면 confidence를 낮추고, 보안상 안전한 쪽(정탐 의심)으로 기운다.
5. 제공된 URI/본문(디코딩)을 '끝까지' 읽어라. 그 안에 SQL 구문(UNION SELECT, OR 1=1,
   SELECT ... FROM, SELECT COUNT(...), 주석 /**/), 스크립트(<script, onerror=, <svg, document.cookie),
   OS명령·경로(;ls, |sh, cmd=, ../../, /etc/passwd)이 '실제로 존재'하면, 절대 '페이로드 없음/정보 부족'
   이라고 말하지 말고 반드시 정탐으로 판정한다. (URI가 길어도 중간에 멈추지 말 것)"""

# 신뢰도 책정 기준(루브릭) — 점수 의미를 고정해 일관성 확보
_CONFIDENCE_RUBRIC = """[신뢰도(confidence) 책정 기준]
- 90~100: 페이로드에 공격 구문이 명확히 존재해 이론의 여지가 거의 없음
- 70~89 : 공격 정황이 강하나 일부 모호하거나 컨텍스트 부족
- 50~69 : 정탐/오탐 판단이 애매하여 추가 확인 필요
- 0~49  : 근거가 약하거나 정보가 부족함
각 경보마다 confidence 점수를 매기고, '왜 그 점수인지'를 confidence_reason에 한 문장으로 반드시 적는다.
(예: "디코딩된 URI에 UNION SELECT 구문이 그대로 존재해 100에 가까움" /
     "정상 페이지네이션 파라미터만 있어 공격 근거 없음")"""

_OUT_FIELDS = """{"id": 1, "verdict": "정탐|오탐", "confidence": 0~100,
   "confidence_reason": "신뢰도 점수의 근거(한 문장)",
   "attack_type": "확정 공격 유형(오탐이면 '해당없음')",
   "reasoning": "정/오탐 판단 근거(한국어 1~2문장)",
   "indicators": ["근거가 된 페이로드 조각들"],
   "recommended_action": "권고 조치(한 문장)"}"""

_BATCH_SYSTEM_PROMPT = f"""당신은 SOC(보안관제센터)의 시니어 침해대응 분석가입니다.
IDS/WAF가 탐지한 보안 경보 '여러 건'을 각각 정탐/오탐으로 판별합니다.

{_CRITERIA}

{_CONFIDENCE_RUBRIC}

입력된 모든 경보를 판별해 'JSON 배열 하나만' 출력한다. 다른 설명/마크다운 금지.
각 원소는 입력 경보 번호(id)와 1:1 대응해야 한다.
[
  {_OUT_FIELDS},
  ...
]"""

# ── 상관탐지(SIEM notable) 전용 판별 기준 ──
# 단일 페이로드가 아니라 '룰 의미 + 기여 이벤트(근거) + 집계 요약'을 보고 행위 기반으로 판단한다.
_CORR_CRITERIA = """[상관탐지 판별 기준]
- 정탐(true_positive): 룰이 정의한 공격 '행위'가 기여 이벤트(근거)에서 실제로 확인됨.
  · 근거 요청/페이로드에 공격 구문이 있거나(예: SQLi·경로순회),
  · 행위 패턴이 근거 수치/이벤트로 뒷받침됨(예: 한 세션 다중 출발지 IP, 대량 요청·5xx 급증,
    단일 대상 집중 플러드, 다단계 킬체인, 경로순회 후 200 응답=유출 정황 등).
- 오탐(false_positive): 룰은 매칭됐으나 '근거를 보면 정상으로 명확히 설명'됨.
  · 인가된 취약점 스캐너·헬스체크·모니터링 봇, 정상 관리자/배치 작업, 명시적 테스트 트래픽,
  · 근거가 정상 파라미터·정상 응답뿐이고 공격 정황이 전혀 없음.

[상관탐지 판별 원칙]
1. 룰 이름만 믿지 말고 '기여 이벤트(evidence)'의 실제 내용·수치를 근거로 판단한다.
2. 상관탐지는 다중 근거로 걸러진 고신뢰 이벤트다. '페이로드 없음/정보 부족'을 이유로
   오탐 처리하지 말 것 — 행위(건수·분산 IP·시간 집중·다단계)가 근거면 정탐이다.
3. 오탐은 근거에 '정상으로 설명되는 명확한 이유'가 있을 때만 내린다. 애매하면 정탐으로 기운다.
4. attack_type에는 rule_title/MITRE 기반 공격 유형을, indicators에는 근거가 된 이벤트 조각을 적는다."""

_CORR_SYSTEM_PROMPT = f"""당신은 SOC(보안관제센터)의 시니어 침해대응 분석가입니다.
SIEM '상관룰'이 다중 근거로 탐지한 보안 이벤트 '여러 건'을 각각 정탐/오탐으로 판별합니다.
각 이벤트는 (룰 의미·MITRE·위험도) + (집계 요약) + (기여 이벤트=실제 트리거 로그)로 제공됩니다.

{_CORR_CRITERIA}

{_CONFIDENCE_RUBRIC}

입력된 모든 상관탐지를 판별해 'JSON 배열 하나만' 출력한다. 다른 설명/마크다운 금지.
각 원소는 입력 번호(id)와 1:1 대응해야 한다.
[
  {_OUT_FIELDS},
  ...
]"""


def _decode(s: str) -> str:
    if not s:
        return ""
    try:
        return unquote_plus(s)
    except Exception:
        return s


# 공격 의도가 담긴 값(payload)을 가려내는 휴리스틱 — 정상 파라미터(userId 등)는 제외
_SUSPECT_RE = re.compile(
    r"""['"<>();|]|\.\.[/\\]|--|\bunion\b|\bselect\b|\bor\b\s+\d|<script|onerror=|onload=|"""
    r"""javascript:|\$\(|&&|\|\||/etc/|/bin/|cmd=|exec\b|0x[0-9a-f]{2}""",
    re.IGNORECASE,
)


def _payload_fingerprint(a: dict[str, Any]) -> str:
    """URI 쿼리 + POST 본문에서 '공격 payload 값'만 추출해 지문을 만든다.

    정상 파라미터(userId, password 등)는 버리고 공격 문자가 든 값만 남기므로,
    같은 공격이 GET(쿼리)·POST(본문)로 갈려 들어와도 동일 지문으로 묶인다.
    예) GET /loginForm.do?returnUrl="><script>... 와
        POST /loginAction.do (본문 userId=a&password=b&returnUrl="><script>...)
        → 둘 다 지문 = returnurl="><script>...
    """
    uri = _decode(a.get("uri", "") or "")
    body = _decode(a.get("body", "") or "")   # status는 이제 HTTP 응답코드라 본문으로 쓰지 않음
    query = uri.split("?", 1)[1] if "?" in uri else ""
    combined = "&".join(filter(None, [query, body]))
    tokens = [t.strip() for t in combined.split("&") if t.strip()]
    suspicious = sorted({t.lower() for t in tokens if _SUSPECT_RE.search(t)})
    if suspicious:
        return " ".join(suspicious)
    if tokens:                                   # 의심 토큰이 없으면 전체 파라미터로 폴백
        return "&".join(sorted(t.lower() for t in tokens))
    return ""


def _payload_sig(a: dict[str, Any]) -> str:
    """병합 키용 페이로드 지문. 페이로드 '구조'가 다르면 다른 값을 돌려준다.

    숫자 리터럴(예: id=1 vs id=2, union select 1,2 vs 1,2,3)만 다른 난사 변형은
    같은 지문으로 묶어 티켓 폭주를 막는다. 페이로드가 없으면 ''(→ IP+유형+시간으로 병합).
    """
    fp = _payload_fingerprint(a)
    return re.sub(r"\d+", "#", fp) if fp else ""


# 결정적(명백한) 공격 구문 — AI가 오탐/저신뢰로 판정해도 이 패턴이 보이면 정탐으로 보정한다.
# (gemini-flash가 배치 판정에서 명백한 SQLi/XSS/RCE를 '페이로드 없음'이라 환각하는 사례 방어)
_STRONG_RE = re.compile(
    r"union\s+select|select\s+.{0,40}?\s+from\s+|select\s+count\s*\(|"
    r"\bor\b\s*\(?\s*'?1'?\s*=\s*'?1|\bor\b\s+\d+\s*=\s*\d+|sleep\s*\(|benchmark\s*\(|"
    r"waitfor\s+delay|information_schema|xp_cmdshell|"                         # SQLi
    r"<script|onerror\s*=|onload\s*=|onmouseover\s*=|<svg\b|<iframe\b|"
    r"<img[^>]{0,40}src\s*=\s*x|javascript:|document\.cookie|"                 # XSS
    r"\.\./\.\./|/etc/passwd|/bin/(?:ba)?sh|\|\s*sh\b|webshell|\bcmd=|"
    r";\s*(?:ls|cat|id|whoami|curl|wget|nc)\b|%2e%2e%2f|etc%2fpasswd",         # RCE/LFI
    re.IGNORECASE,
)


def _strong_attack_signal(rep: dict[str, Any]) -> str:
    """대표 경보(URI/본문/지문)에 결정적 공격 구문이 있으면 매칭 문자열, 없으면 ''."""
    blob = " ".join([
        _decode(str(rep.get("uri", "") or "")),
        _decode(str(rep.get("body", "") or "")),
        _payload_fingerprint(rep),
    ])
    blob = re.sub(r"/\*.*?\*/", " ", blob)   # SQL 주석(/**/) 우회 제거 후 매칭
    m = _STRONG_RE.search(blob)
    return m.group(0).strip() if m else ""


def _flood_volume(rep: dict[str, Any]) -> int:
    """대량성 공격의 '볼륨' = 단일 대상에 묶인 건수와 분산 출발지 수 중 큰 값."""
    return max(
        int(rep.get("merged_count") or 0),
        int(rep.get("merged_src_count") or 0),
    )


def _normalize_category(sig: str) -> str:
    """소스별 시그니처를 공통 공격유형으로 정규화한다.

    'XSS' / 'XSS (Snort)' / '[YANUS CUSTOM] [XSS] ...' / 'ET WEB_SERVER Script tag...'
    → 모두 'XSS'. 소스(WAF/Snort/IDS)가 달라도 같은 유형으로 묶기 위함.
    """
    s = (sig or "").lower()
    if re.search(r"sql", s):
        return "SQL Injection"
    if re.search(r"xss|cross.?site|\bscript\b|script tag", s):
        return "XSS"
    if re.search(r"\brce\b|command|remote.code|os.command", s):
        return "RCE/Command Injection"
    if re.search(r"\blfi\b|\brfi\b|traversal|/etc/|passwd|file.inclusion|path traversal", s):
        return "LFI/Path Traversal"
    if re.search(r"brute|failed.password|invalid.user", s):
        return "Brute Force"
    if re.search(r"port.?scan|nmap|recon|sweep|\bscan\b", s):
        return "Port Scan"
    if re.search(r"upload|webshell", s):
        return "File Upload/Webshell"
    if re.search(r"ddos|flood|denial", s):
        return "DDoS"
    if re.search(r"session|fixation", s):
        return "Session"
    if re.search(r"http.anomaly|chunk|http_inspect|anomaly", s):
        return "HTTP Anomaly"
    base = re.sub(r"\s*\((snort|ids|waf)\)\s*$", "", sig or "", flags=re.I)
    base = re.sub(r"^\[yanus custom\]\s*\[[^\]]*\]\s*", "", base, flags=re.I).strip()
    return base or "기타"


def _epoch(t: Any) -> float:
    """Splunk _time(ISO8601, 예: '2026-06-12T17:45:54.000+09:00')을 epoch 초로."""
    if not t:
        return 0.0
    s = str(t).strip()
    try:
        return datetime.fromisoformat(s).timestamp()
    except Exception:
        m = re.match(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})", s)
        if m:
            try:
                return datetime.fromisoformat(f"{m.group(1)}T{m.group(2)}").timestamp()
            except Exception:
                return 0.0
    return 0.0


# '다수 출발지 → 단일 대상'인 대량성 공격만 출발지를 무시하고 '대상(dest)'으로 묶는다.
# DDoS는 봇넷/스푸핑으로 출발지가 수천 개라, src 기준이면 인시던트(=티켓)가 폭증한다.
# 그 외(SQLi·XSS·RCE·웹쉘·LFI·Port Scan 등)는 '출발지=공격자'이므로 종전대로 src 기준 유지.
_FLOOD_CATEGORIES = {"DDoS"}


def _dedup_key(a: dict[str, Any]) -> str:
    """상관(correlation) 키 = 정규화된 공격유형 + (출발지 또는 대상) + [페이로드] + 시간 윈도우.

    - 일반 공격: '유형 + 출발지IP + 페이로드지문 + 시간윈도우'
      · 같은 공격자의 멀티센서·동일 페이로드 GET/POST 버스트는 1건으로 묶임(지문 동일).
      · 페이로드 구조가 다르면(예: ' OR 1=1 vs UNION SELECT) 별도 인시던트로 분리.
        (config.TRIAGE_SPLIT_BY_PAYLOAD=False면 종전처럼 페이로드 무시하고 IP+유형으로만 병합)
    - 대량성(DDoS): '유형 + 대상IP + 시간윈도우' — 분산 출발지를 대상 기준 캠페인 1건으로 묶음.
      (출발지들은 버리지 않고 auto_triage에서 merged_src_ips/merged_src_count로 보존)
    윈도우(config.TRIAGE_MERGE_WINDOW_SEC, 기본 30분)를 벗어난 새 공격은 새 인시던트로 분리된다.
    """
    cat = _normalize_category(str(a.get("signature", "")))
    win = config.TRIAGE_MERGE_WINDOW_SEC
    bucket = int(_epoch(a.get("_time")) // win) if win > 0 else 0
    # 상관탐지(SIEM notable): 룰이 매분 새 노터블을 만들고 근거(evidence)에 매번 다른 로그·시각·
    # 명령줄이 섞여 payload 지문이 주기마다 바뀐다 → 같은 인시던트가 중복방지를 못 뚫고 반복 전달됨.
    # 따라서 페이로드 지문을 키에 넣지 않고 'rule_id + 엔티티(출발지/자산) + 일(日) 버킷'으로
    # 한 인시던트=한 티켓이 되게 한다(같은 룰·대상은 하루 1건).
    if str(a.get("detection_class")) == "correlation":
        rid = str(a.get("rule_id") or cat)
        anchor = str(a.get("src_ip") or a.get("asset") or a.get("entity") or "*")
        cwin = config.TRIAGE_CORR_WINDOW_SEC          # 기본 60초(1분당 1티켓)
        slot = int(_epoch(a.get("_time")) // cwin) if cwin > 0 else 0
        return f"corr|{rid}|{anchor}|{slot}"
    if cat in _FLOOD_CATEGORIES:
        anchor = str(a.get("dest_ip", "")) or "*"   # 대상 기준(출발지 무시)
        return f"{cat}|dst:{anchor}|{bucket}"
    ip = str(a.get("src_ip", ""))                   # 일반: 출발지=공격자
    if config.TRIAGE_SPLIT_BY_PAYLOAD:
        sig = _payload_sig(a)                        # 페이로드 구조 — 다르면 분리
        if sig:
            return f"{cat}|{ip}|{sig}|{bucket}"
    return f"{cat}|{ip}|{bucket}"


def _pick_representative(members: list[dict[str, Any]]) -> dict[str, Any]:
    """그룹 내에서 'payload 증거가 가장 풍부한' 경보를 AI 판정 대표로 고른다.

    Snort/IDS(룰명만)보다 WAF(실제 payload 보유)를 우선 → 판정 정확도↑.
    """
    def score(m: dict[str, Any]) -> tuple:
        fp = _payload_fingerprint(m)
        has_payload = 1 if _SUSPECT_RE.search(fp) else 0
        is_waf = 1 if str(m.get("source") or m.get("source_type") or "") == "WAF Web" else 0
        return (has_payload, len(fp), is_waf)
    return max(members, key=score)


def _alert_block(a: dict[str, Any]) -> list[str]:
    uri_dec = _decode(a.get("uri", "") or "")
    body_dec = _decode(a.get("body", "") or "").strip()   # POST 본문(modsec C 섹션)
    http_status = str(a.get("status", "") or "").strip()  # HTTP 응답코드(200/302/403 등)
    lines = [
        f"- 탐지 시그니처: {a.get('signature', '(없음)')}",
        f"- 출발지 IP: {a.get('src_ip', '?')}  목적지 IP: {a.get('dest_ip', '?')}",
        f"- 탐지원: {a.get('source', '?')}  위험도(원본): {a.get('severity', '?')}",
        f"- URI(디코딩): {uri_dec or '(없음)'}",
    ]
    if body_dec:
        lines.append(f"- 본문/파라미터(디코딩): {body_dec}")
    if http_status:
        lines.append(f"- HTTP 응답코드: {http_status} (200=서버 도달, 403/406=WAF 차단)")
    return lines


def _build_batch_prompt(alerts: list[dict[str, Any]]) -> str:
    lines = [f"[판별 대상 보안 경보 {len(alerts)}건]"]
    for i, a in enumerate(alerts, 1):
        lines.append(f"\n■ 경보 #{i}")
        lines.extend(_alert_block(a))
    lines.append(f"\n위 {len(alerts)}건을 각각 판별해 id를 포함한 JSON 배열로만 출력하세요.")
    return "\n".join(lines)


# modsec 원시로그/본문에서 '실제 공격 페이로드' 조각을 뽑는 패턴
_INDICATOR_RE = re.compile(r"ARGS:[\w.\-]+:\s*([^\"\]\r\n]{2,200})", re.IGNORECASE)
_MATCHED_RE = re.compile(r"Matched Data:\s*([^\"\]\r\n]{2,200})", re.IGNORECASE)


def _extract_indicator(raw: str) -> str:
    """request_raw(modsec 감사로그) 등 긴 텍스트에서 공격 페이로드 조각만 뽑아 LLM에 노출한다.

    payload 필드가 비어 있고 공격 구문이 원시로그 깊숙이(modsec 메시지/본문) 묻혀 있을 때,
    그 부분이 truncation에 잘려 LLM이 '페이로드 없음'으로 오판하는 것을 막는다.
    """
    if not raw:
        return ""
    m = _INDICATOR_RE.search(raw) or _MATCHED_RE.search(raw)
    if m:
        return m.group(1).strip()
    dec = _decode(raw)
    # 명백한 공격 구문(_STRONG_RE)만 추출한다. 느슨한 _SUSPECT_RE 폴백은
    # Snort 알람줄/JSON 같은 메타데이터에서 단어 중간을 잘라 가짜 페이로드를 만들어 제거.
    hit = _STRONG_RE.search(dec)
    return dec[hit.start():hit.start() + 140].strip() if hit else ""


def _evidence_block(ev_list: Any, limit: int = 8) -> list[str]:
    """기여 이벤트(evidence) 배열을 LLM이 읽을 수 있는 줄로 펼친다.

    핵심: 디코딩된 payload(없으면 request_raw에서 추출한 공격 구문)를 '★공격페이로드='로 맨 앞에
    노출 → 공격 페이로드가 잘려서 안 보이는 문제를 해소(보정 없이도 LLM이 판정 가능).
    """
    out: list[str] = []
    items = ev_list if isinstance(ev_list, list) else []
    _skip = {"request_raw", "raw", "payload", "injected_params"}   # 아래서 ★공격페이로드로 대표 노출
    for j, e in enumerate(items[:limit], 1):
        if not isinstance(e, dict):
            out.append(f"   {j}) {str(e)[:240]}")
            continue
        # 주입 파라미터·페이로드(룰별 키: payload/injected_params). 플레이스홀더 '(…)'는 제외
        rawp = str(e.get("payload") or e.get("injected_params") or "").strip()
        atk = "" if rawp.startswith("(") else _decode(rawp)
        if not atk:
            atk = _extract_indicator(str(e.get("request_raw") or e.get("raw") or ""))
        kvs = []
        for k, v in e.items():
            if k in _skip or v in (None, ""):
                continue
            s = _decode(str(v)) if k == "uri" else str(v)
            kvs.append(f"{k}={s[:200]}")
        if atk:
            kvs.insert(0, f"★공격페이로드={atk[:300]}")
        out.append(f"   {j}) " + " | ".join(kvs))
    return out


def _build_corr_prompt(alerts: list[dict[str, Any]]) -> str:
    lines = [f"[판별 대상 상관탐지 {len(alerts)}건]"]
    for i, a in enumerate(alerts, 1):
        lines.append(f"\n■ 상관탐지 #{i}")
        lines.append(f"- 룰: {a.get('rule_id', '')} {a.get('rule_title', '')}  (MITRE: {a.get('mitre', '-') or '-'})")
        lines.append(f"- 원본 위험도: severity {a.get('severity', '?')} / risk {a.get('risk_score', '?')} {a.get('risk_band', '') or ''}")
        lines.append(f"- 엔티티: {a.get('entity', '?')}   대상: {a.get('dest_ip', '-') or '-'}")
        summ = a.get("summary")
        if isinstance(summ, dict) and summ:
            lines.append(f"- 집계 요약: {json.dumps(summ, ensure_ascii=False)[:700]}")
        ev = a.get("evidence")
        ev_count = a.get("evidence_count", len(ev) if isinstance(ev, list) else 0)
        lines.append(f"- 기여 이벤트({ev_count}건):")
        ev_lines = _evidence_block(ev)
        lines.extend(ev_lines if ev_lines else ["   (기여 이벤트 없음 — 룰 의미와 집계 요약으로 판단)"])
    lines.append(f"\n위 {len(alerts)}건을 각각 판별해 id를 포함한 JSON 배열로만 출력하세요.")
    return "\n".join(lines)


def _extract_json(text: str) -> Any:
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.IGNORECASE).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"(\[.*\]|\{.*\})", text, flags=re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            pass
    if _json_repair is not None:    # 따옴표 미이스케이프·배열에 객체 삽입 등 모델 JSON 오류 복구
        return _json_repair.loads(text)
    raise json.JSONDecodeError("JSON 추출 실패", text, 0)


def _as_list(arr: Any) -> list:
    """파싱 결과를 '항목 리스트'로 정규화 — 배열/단일객체/{...:[...]} 래핑 모두 수용."""
    if isinstance(arr, list):
        return arr
    if isinstance(arr, dict):
        for v in arr.values():
            if isinstance(v, list):
                return v
        return [arr]
    return []


def _safe_id(x: dict, i: int) -> int:
    try:
        return int(x.get("id", i))
    except Exception:  # noqa: BLE001
        return i


def _model_name() -> str:
    m = config.GEMINI_MODEL
    return m if "/" in m else f"google/{m}"


def _call(system: str, user: str) -> str:
    resp = requests.post(
        _OR_URL,
        headers={"Authorization": f"Bearer {config.GEMINI_API_KEY}", "Content-Type": "application/json"},
        json={
            "model": _model_name(),
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0,
            "response_format": {"type": "json_object"},   # 유효 JSON 강제(배열도 허용됨)
        },
        timeout=180,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _clean_indicators(v: dict[str, Any]) -> None:
    """indicators를 '문자열 리스트'로 강제(모델이 배열에 dict를 넣는 경우 방어 →
    하류의 ' '.join() 크래시·렌더 오류 방지)."""
    inds = v.get("indicators")
    if isinstance(inds, list):
        v["indicators"] = [x if isinstance(x, str)
                           else (json.dumps(x, ensure_ascii=False) if isinstance(x, dict) else str(x))
                           for x in inds]
    elif inds is not None:
        v["indicators"] = [str(inds)]


def _normalize(v: dict[str, Any]) -> dict[str, Any]:
    v.setdefault("verdict", "정탐")
    v.setdefault("confidence", 0)
    v.setdefault("confidence_reason", "")
    _clean_indicators(v)
    v["is_true_positive"] = str(v.get("verdict", "")).startswith("정탐")
    return v


_FALLBACK = {"verdict": "정탐", "confidence": 0, "confidence_reason": "AI 응답 파싱 실패",
             "attack_type": "판별불가", "reasoning": "AI 응답 파싱 실패 — 수동 검토 필요",
             "indicators": [], "recommended_action": "수동 검토 필요",
             "is_true_positive": True, "_parse_error": True}


def _load_cache() -> dict[str, dict]:
    try:
        cache = json.loads(_CACHE_FILE.read_text(encoding="utf-8-sig"))   # BOM 내성
        for v in cache.values():               # 기존 verdict의 indicators 정리(dict 원소 제거)
            if isinstance(v, dict):
                _clean_indicators(v)
        return cache
    except Exception:
        return {}


def _save_cache(cache: dict[str, dict]) -> None:
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


class TriageService:
    def __init__(self) -> None:
        self._cache = _load_cache()   # dedup_key -> verdict

    def classify_batch(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not alerts:
            return []
        try:
            arr = _as_list(_extract_json(_call(_BATCH_SYSTEM_PROMPT, _build_batch_prompt(alerts))))
        except Exception:
            arr = []
        by_id = {_safe_id(x, i): x for i, x in enumerate(arr, 1) if isinstance(x, dict)}
        return [_normalize(by_id[i]) if by_id.get(i) else dict(_FALLBACK) for i in range(1, len(alerts) + 1)]

    def classify_correlation_batch(self, alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """상관탐지(SIEM notable) 전용 판정 — 룰 의미 + 기여 이벤트(근거)로 행위 기반 판단."""
        if not alerts:
            return []
        try:
            arr = _as_list(_extract_json(_call(_CORR_SYSTEM_PROMPT, _build_corr_prompt(alerts))))
        except Exception:
            arr = []
        by_id = {_safe_id(x, i): x for i, x in enumerate(arr, 1) if isinstance(x, dict)}
        return [_normalize(by_id[i]) if by_id.get(i) else dict(_FALLBACK) for i in range(1, len(alerts) + 1)]

    def auto_triage(self, alerts: list[dict[str, Any]], max_batch: int = 8) -> dict[str, Any]:
        """경보를 상관(correlation) 그룹으로 묶어 자동 판정.

        - 같은 출발지+공격유형은 소스(WAF·Snort·IDS) 무관하게 1개 인시던트로 병합.
        - 그룹마다 payload가 가장 풍부한 대표 경보 1건만 LLM 판정(비용 절감) → 그룹 전체에 적용.
        - 신규(미캐시) 그룹만 LLM 호출.
        - 결과는 그룹당 1행으로 반환("한 공격 = 한 티켓").
        """
        # 1) 상관 그룹핑(유형+IP), 입력 순서 유지
        groups: dict[str, list[dict[str, Any]]] = {}
        order: list[str] = []
        for a in alerts:
            k = _dedup_key(a)
            if k not in groups:
                groups[k] = []
                order.append(k)
            groups[k].append(a)

        # 2) 캐시에 없는 신규 그룹만 대표 경보로 배치 판정
        #    detection_class에 따라 판정기를 분기: 상관탐지는 근거(evidence) 기반 상관 분류기,
        #    그 외(단일 장비 alert)는 페이로드 기반 분류기.
        new_keys = [k for k in order if k not in self._cache]
        if new_keys:
            reps = {k: _pick_representative(groups[k]) for k in new_keys}
            corr_keys = [k for k in new_keys if str(reps[k].get("detection_class")) == "correlation"]
            base_keys = [k for k in new_keys if str(reps[k].get("detection_class")) != "correlation"]

            def _judge(keys, classifier, batch):
                for i in range(0, len(keys), batch):
                    ck = keys[i:i + batch]
                    for k, v in zip(ck, classifier([reps[k] for k in ck])):
                        if v.get("_parse_error"):
                            continue          # 파싱 실패는 캐시하지 않음 → 다음 주기 자동 재시도
                        self._cache[k] = v

            _judge(base_keys, self.classify_batch, max_batch)
            _judge(corr_keys, self.classify_correlation_batch, max(3, max_batch // 2))  # 근거가 길어 작은 배치
            _save_cache(self._cache)

        # 3) 그룹당 1행으로 병합 결과 구성
        results = []
        for k in order:
            members = groups[k]
            rep = dict(_pick_representative(members))
            sources = sorted({str(m.get("source") or m.get("source_type") or "?") for m in members if (m.get("source") or m.get("source_type"))})
            sigs = sorted({str(m.get("signature") or "") for m in members if m.get("signature")})
            src_ips = sorted({str(m.get("src_ip") or "") for m in members if m.get("src_ip")})
            rep["merged_count"] = len(members)
            rep["merged_sources"] = sources
            rep["merged_signatures"] = sigs
            rep["merged_src_ips"] = src_ips[:50]      # 대표 표시용(상한)
            rep["merged_src_count"] = len(src_ips)    # 분산 DDoS의 출발지 수
            triage = dict(self._cache.get(k, dict(_FALLBACK)))
            # 결정적 공격 구문이면 AI 오탐을 정탐으로 보정(캐시 여부 무관, 보안 우선)
            sig = _strong_attack_signal(rep)
            if sig and not triage.get("is_true_positive"):
                triage.update(
                    verdict="정탐", is_true_positive=True,
                    confidence=max(int(triage.get("confidence") or 0), 90),
                    attack_type=(triage.get("attack_type") if triage.get("attack_type") not in ("", "해당없음", None) else "공격(자동판정)"),
                    reasoning=f"디코딩된 페이로드에 공격 구문 '{sig}'이(가) 존재해 정탐 확정(결정적 보정). "
                              f"AI 초기판정(오탐)은 페이로드 미인식이므로 무효 처리함.",
                    confidence_reason=f"페이로드에 '{sig}' 명시적으로 존재 — 결정적 보정",
                    _override=True)
            # 볼륨 기반 보정: DDoS 등 대량성 공격은 페이로드가 없어 내용 기반 LLM이
            # 오탐으로 보기 쉽다. 단일 대상 집중 건수/출발지 수가 임계치 이상이면 정탐 확정.
            cat = _normalize_category(str(rep.get("signature", "")))
            vol = _flood_volume(rep)
            if cat in _FLOOD_CATEGORIES and vol >= config.TRIAGE_FLOOD_MIN and not triage.get("is_true_positive"):
                triage.update(
                    verdict="정탐", is_true_positive=True,
                    confidence=max(int(triage.get("confidence") or 0), 85),
                    attack_type=(triage.get("attack_type") if triage.get("attack_type") not in ("", "해당없음", None) else "DDoS"),
                    reasoning=f"단일 대상에 대량성 트래픽 {vol}건 집중(임계 {config.TRIAGE_FLOOD_MIN}) — 볼륨 기반 정탐 보정(페이로드 무관). " + str(triage.get("reasoning") or ""),
                    confidence_reason=f"30분 윈도우 내 동일 대상 {vol}건 집중 — DDoS 볼륨 신호",
                    _override=True)
            # 상관탐지 안전망: 근거 기반 판정(오탐 포함)은 존중하되, 위험도 '심각' 등급은
            # AI가 오탐이라 해도 자동 폐기하지 않고 정탐 유지(사람 검토 강제).
            if (str(rep.get("detection_class")) == "correlation"
                    and not triage.get("is_true_positive")
                    and str(rep.get("risk_band")) == "심각"):
                triage.update(
                    verdict="정탐", is_true_positive=True,
                    confidence=max(int(triage.get("confidence") or 0), 70),
                    attack_type=(triage.get("attack_type") if triage.get("attack_type") not in ("", "해당없음", None) else (rep.get("rule_title") or "상관탐지")),
                    reasoning=f"위험도 '심각' 상관탐지({rep.get('rule_id','')}) — AI 오탐 의견이나 자동 폐기 없이 정탐 유지(사람 검토 필요). " + str(triage.get("reasoning") or ""),
                    confidence_reason="심각 등급 상관탐지 — 자동 오탐 폐기 방지",
                    _override=True)
            results.append({"alert": rep, "triage": triage})

        tp = sum(1 for r in results if r["triage"].get("is_true_positive"))
        return {
            "results": results,
            "counts": {"정탐": tp, "오탐": len(results) - tp, "total": len(results),
                       "신규판정": len(new_keys), "원본경보수": len(alerts)},
        }


triage_service = TriageService()
