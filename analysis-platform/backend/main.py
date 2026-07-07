"""사령탑 — FastAPI 애플리케이션.

- 스플렁크 alert action(웹훅) 수신
- 프론트엔드용 데이터 API 제공
- 분석 트리거 및 PDF 보고서 생성/다운로드
- 경보 유입 시 LLM 정·오탐 자동 판정(백그라운드)
"""
import threading
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import config
from cve_service import cve_service
from gemini_service import gemini_service
from insights_service import insights_service
from report_generator import generate_report
from forwarder_service import forwarder_service
from crisis_service import get_crisis_level
import dashboard_service
from splunk_client import splunk_client
from threat_intel_service import threat_intel_service
from triage_service import triage_service, _dedup_key, _pick_representative

app = FastAPI(title="SOC 분석 플랫폼", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 인트라넷 내부망 전제. 운영 시 프론트 출처로 제한 권장
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _start_auto_triage() -> None:
    """경보 유입 시 자동 정·오탐 판정 + 정탐 자동 전달. 60초 주기.

    1) 신규 고유 경보만 LLM 판정(캐시 재사용)
    2) 정탐만 소통플랫폼으로 전달(이미 보낸 건은 제외)
    """
    def loop() -> None:
        while True:
            try:
                evs = splunk_client.recent_alerts(earliest="-24h")
                result = triage_service.auto_triage((evs or [])[:80])
                forwarder_service.forward_true_positives(result)
            except Exception:
                pass
            time.sleep(60)
    threading.Thread(target=loop, daemon=True).start()


class SearchRequest(BaseModel):
    spl: str
    earliest: str = "-24h"
    latest: str = "now"


class AnalyzeRequest(BaseModel):
    spl: str | None = None
    events: list[dict[str, Any]] | None = None
    context: str = ""
    title: str = "이벤트 분석 보고서"


class ChatRequest(BaseModel):
    question: str
    history: list[dict[str, str]] = []


class TriageRequest(BaseModel):
    events: list[dict[str, Any]] | None = None   # 미제공 시 최근 알림 조회
    earliest: str = "-24h"
    limit: int = 60


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/crisis-level")
def crisis_level() -> dict[str, Any]:
    """국내 사이버 위기 경보단계 (KISA 보호나라/KrCERT 실시간 파싱·캐시)."""
    return get_crisis_level()


@app.get("/api/dashboard/news")
def dashboard_news() -> dict[str, Any]:
    """보안 뉴스 헤드라인 (보안뉴스 RSS·캐시)."""
    return {"items": dashboard_service.security_news(), "source": "보안뉴스"}


@app.get("/api/dashboard/advisories")
def dashboard_advisories() -> dict[str, Any]:
    """기관 보안 권고·공지 (KrCERT 보안공지·캐시)."""
    return {"items": dashboard_service.advisories(), "source": "KrCERT 보안공지"}


@app.get("/api/alerts")
def get_alerts(index: str = "*", earliest: str = "-24h", latest: str = "now") -> dict[str, Any]:
    """대시보드용 최근 알림 목록."""
    try:
        rows = splunk_client.recent_alerts(index=index, earliest=earliest, latest=latest)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"스플렁크 조회 실패: {exc}") from exc
    return {"count": len(rows), "alerts": rows}


def _merged_incidents(earliest: str = "-24h", latest: str = "now") -> list[dict[str, Any]]:
    """notable 상관탐지를 '한 공격=한 인시던트'로 병합(LLM 없이 dedup_key 그룹핑)해
    대표 경보(+병합건수 merged_count)의 리스트를 반환한다. 기록 탭과 동일 기준.
    head 제한 없이(머지 전 전체) 가져오므로 일부 공격유형이 누락되지 않는다.
    """
    raw = splunk_client.recent_notables(earliest=earliest, latest=latest, head=10000)
    groups: dict[str, list[dict[str, Any]]] = {}
    for e in raw:
        groups.setdefault(_dedup_key(e), []).append(e)
    out: list[dict[str, Any]] = []
    for members in groups.values():
        rep = dict(_pick_representative(members))
        rep["merged_count"] = len(members)
        out.append(rep)
    return out


@app.get("/api/alerts/summary")
def get_alerts_summary(earliest: str = "-24h", latest: str = "now") -> dict[str, Any]:
    """금일 위협 현황 집계 — 이벤트 피드/기록과 동일 소스.

    notable 모드(실서버): 상관탐지를 '한 공격=한 인시던트'로 병합해 인시던트 단위로 집계
    → 기록 탭과 동일한 건수를 보장한다. 그 외/mock: soc_base를 (시그니처,위험도)별로 집계.
    """
    try:
        if config.ALERT_SOURCE == "notable" and not config.SOC_MOCK:
            rows = [{"signature": i.get("signature") or "상관탐지",
                     "severity": i.get("severity") if i.get("severity") is not None else 0,
                     "count": 1} for i in _merged_incidents(earliest, latest)]
            return {"rows": rows}
        rows = splunk_client.alert_summary(earliest=earliest, latest=latest)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"스플렁크 집계 실패: {exc}") from exc
    return {"rows": rows}


@app.get("/api/alerts/geo")
def get_alerts_geo(earliest: str = "-24h", latest: str = "now", limit: int = 150) -> dict[str, Any]:
    """지구본 호(arc)용 집계 — 24h 전체 출발지→목적지→시그니처 흐름(상위 limit개)."""
    try:
        flows = splunk_client.alert_geo(earliest=earliest, latest=latest, limit=limit)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"스플렁크 집계 실패: {exc}") from exc
    return {"flows": flows}


@app.get("/api/triage")
def triage_view(earliest: str = "-24h", limit: int = 80) -> dict[str, Any]:
    """정·오탐 자동 판정 결과 조회 — 경보를 자동 분류(신규만 LLM 호출, 캐시 재사용)."""
    try:
        events = splunk_client.recent_alerts(earliest=earliest)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"스플렁크 조회 실패: {exc}") from exc
    events = (events or [])[:limit]
    if not events:
        return {"results": [], "counts": {"정탐": 0, "오탐": 0, "total": 0, "신규판정": 0}}
    try:
        return triage_service.auto_triage(events)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI 판정 실패: {exc}") from exc


@app.get("/api/triage/history")
def triage_history(earliest: str = "-90d", head: int = 2000) -> dict[str, Any]:
    """탐지 기록(전체) — 100건 제한 없이 기간 내 모든 탐지를 정·오탐 판정과 함께 반환."""
    try:
        if config.ALERT_SOURCE == "notable":
            events = splunk_client.recent_notables(earliest=earliest, head=head)
        else:
            events = splunk_client.recent_alerts(earliest=earliest)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"스플렁크 조회 실패: {exc}") from exc
    if not events:
        return {"results": [], "counts": {"정탐": 0, "오탐": 0, "total": 0, "신규판정": 0}}
    try:
        return triage_service.auto_triage(events)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI 판정 실패: {exc}") from exc


@app.post("/api/triage")
def triage(req: TriageRequest) -> dict[str, Any]:
    """명시적으로 전달한 이벤트(또는 최근 알림)를 자동 판정."""
    events = req.events
    if events is None:
        try:
            events = splunk_client.recent_alerts(earliest=req.earliest)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"스플렁크 조회 실패: {exc}") from exc
    events = (events or [])[: req.limit]
    if not events:
        return {"results": [], "counts": {"정탐": 0, "오탐": 0, "total": 0, "신규판정": 0}}
    try:
        return triage_service.auto_triage(events)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI 판정 실패: {exc}") from exc


@app.post("/api/forward")
def forward_now(req: TriageRequest) -> dict[str, Any]:
    """정탐 이벤트를 소통플랫폼으로 즉시 전달(수동 트리거, 멱등).

    이미 전달한 정탐은 중복 전송하지 않는다. 백그라운드 자동 전달과 동일 로직.
    """
    events = req.events
    if events is None:
        try:
            events = splunk_client.recent_alerts(earliest=req.earliest)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"스플렁크 조회 실패: {exc}") from exc
    events = (events or [])[: req.limit]
    if not events:
        return {"forwarded": 0, "skipped_dup": 0, "total_tp": 0, "ids": []}
    try:
        result = triage_service.auto_triage(events)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI 판정 실패: {exc}") from exc
    out = forwarder_service.forward_true_positives(result)
    if out.get("error"):
        raise HTTPException(status_code=502, detail=f"소통플랫폼 전달 실패: {out['error']}")
    return out


@app.post("/api/search")
def run_search(req: SearchRequest) -> dict[str, Any]:
    """임의 SPL 검색 실행."""
    try:
        rows = splunk_client.search(req.spl, req.earliest, req.latest)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"검색 실패: {exc}") from exc
    return {"count": len(rows), "results": rows}


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest) -> dict[str, Any]:
    """이벤트(또는 SPL 결과)를 Gemini로 분석하고 PDF 보고서를 굽는다."""
    events = req.events
    if events is None:
        if not req.spl:
            raise HTTPException(status_code=400, detail="events 또는 spl 중 하나는 필요합니다.")
        try:
            events = splunk_client.search(req.spl)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"검색 실패: {exc}") from exc

    if not events:
        raise HTTPException(status_code=404, detail="분석할 이벤트가 없습니다.")

    # TI 보강: 외부 IP 평판을 context에 추가해 Gemini 분석 품질을 높인다
    try:
        ti_data = threat_intel_service.enrich_events(events)
        ti_context = _format_ti_context(ti_data)
    except Exception:
        ti_data, ti_context = {}, ""

    combined_context = "\n\n".join(filter(None, [req.context, ti_context]))

    try:
        analysis = gemini_service.analyze_incident(events, combined_context)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI 분석 실패: {exc}") from exc

    pdf_path = generate_report(req.title, analysis, events)
    return {
        "analysis": analysis,
        "report_file": pdf_path.name,
        "event_count": len(events),
        "ti_enriched": len(ti_data),
    }


class EventReportRequest(BaseModel):
    events: list[dict[str, Any]]
    title: str | None = None


@app.post("/api/report/event")
def event_report(req: EventReportRequest) -> dict[str, Any]:
    """이벤트 → HTML 템플릿 기반 '이벤트 분석 보고서' PDF 생성.

    위험도 배너·공격 플로우·킬체인 단계(MITRE)·대응 액션(P1~P3)·연계 이벤트 카드.
    (corr_to_report로 정규화 → Jinja2 렌더 → Edge/Chromium 또는 WeasyPrint로 PDF)
    """
    if not req.events:
        raise HTTPException(status_code=400, detail="이벤트가 필요합니다.")
    # AI 종합 분석(상세 서술) — 실패해도 구조화 보고서는 생성
    analysis = None
    try:
        analysis = gemini_service.analyze_incident(req.events)
    except Exception:
        analysis = None
    try:
        from render_report import generate_event_report
        out, engine = generate_event_report(req.events, title=req.title, analysis=analysis)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"보고서 생성 실패: {exc}") from exc
    return {"report_file": out.name, "engine": engine, "event_count": len(req.events)}


@app.post("/api/report/event/html", response_class=HTMLResponse)
def event_report_html(req: EventReportRequest) -> HTMLResponse:
    """이벤트 → 보고서 HTML(자체 완결, 인라인 CSS). 브라우저에서 열어
    인쇄 → 'PDF로 저장'(Ctrl+P)으로 내보낼 수 있다(서버 렌더러 불필요)."""
    if not req.events:
        raise HTTPException(status_code=400, detail="이벤트가 필요합니다.")
    try:
        import corr_to_report
        import render_report
        ctx = corr_to_report.build_context(req.events, title=req.title)
        return HTMLResponse(render_report.render_html(ctx))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"보고서 생성 실패: {exc}") from exc


@app.post("/api/chat")
def chat(req: ChatRequest) -> dict[str, Any]:
    """수집된 로그(최근 24h)를 컨텍스트로 사용자의 질문에 답한다.

    notable 모드: head 100 원시 로그를 그대로 넣으면 노이즈성 룰이 컨텍스트를 차지해
    웹쉘 등 일부 공격이 빠져 '0건'으로 답하는 문제가 있었다. → 누락 없이 전체 24h를
    '한 공격=한 인시던트'로 병합·압축(발생건수 포함)해 모든 공격유형이 보이게 한다.
    """
    if not req.question.strip():
        raise HTTPException(status_code=400, detail="질문이 비어 있습니다.")
    try:
        if config.ALERT_SOURCE == "notable" and not config.SOC_MOCK:
            events = [{
                "공격유형": i.get("signature") or i.get("rule_title") or "상관탐지",
                "rule_id": i.get("rule_id", ""),
                "위험도": i.get("severity"),
                "위험등급": i.get("risk_band", ""),
                "출발지IP": i.get("src_ip") or "",
                "대상": i.get("dest_ip") or i.get("asset") or "",
                "발생건수": i.get("merged_count", 1),
                "대표페이로드": (i.get("payload") or "")[:200],
                "시각": str(i.get("_time") or ""),
            } for i in _merged_incidents("-24h")]
        else:
            events = splunk_client.recent_alerts(earliest="-24h")
    except Exception:
        events = []  # 로그 조회 실패 시 빈 컨텍스트로라도 답변 시도
    try:
        answer = gemini_service.chat(req.question, req.history, events)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"챗봇 응답 실패: {exc}") from exc
    return {"answer": answer, "context_count": len(events)}


@app.post("/webhook/splunk")
async def splunk_webhook(payload: dict[str, Any]) -> dict[str, Any]:
    """스플렁크 alert action 웹훅 수신.

    스플렁크 표준 웹훅 페이로드는 result/results 필드에 트리거된 이벤트를 담는다.
    수신 즉시 자동 분석 후 보고서를 생성한다.
    """
    result = payload.get("result") or payload.get("results")
    if isinstance(result, dict):
        events = [result]
    elif isinstance(result, list):
        events = result
    else:
        events = [payload]

    search_name = payload.get("search_name", "Splunk Alert")
    try:
        analysis = gemini_service.analyze_incident(events, context=f"트리거된 알림: {search_name}")
        pdf_path = generate_report(f"[자동] {search_name}", analysis, events)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"자동 분석 실패: {exc}") from exc

    return {"received": True, "report_file": pdf_path.name, "event_count": len(events)}


@app.get("/api/reports/{filename}")
def download_report(filename: str) -> FileResponse:
    """생성된 PDF 보고서 다운로드."""
    # 경로 탈출 방지
    safe = config.PDF_OUTPUT_DIR / filename
    if safe.parent != config.PDF_OUTPUT_DIR or not safe.exists():
        raise HTTPException(status_code=404, detail="보고서를 찾을 수 없습니다.")
    return FileResponse(
        safe,
        media_type="application/pdf",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/reports")
def list_reports() -> dict[str, list[str]]:
    files = sorted((p.name for p in config.PDF_OUTPUT_DIR.glob("*.pdf")), reverse=True)
    return {"reports": files}


# ------------------------------------------------------------------ #
# Threat Intelligence 엔드포인트
# ------------------------------------------------------------------ #

@app.get("/api/intel/ip/{ip}")
def get_ip_intel(ip: str) -> dict[str, Any]:
    """단일 IP 위협 인텔리전스 조회."""
    try:
        return threat_intel_service.lookup_ip(ip)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"TI 조회 실패: {exc}") from exc


class EnrichRequest(BaseModel):
    events: list[dict[str, Any]]


@app.post("/api/intel/enrich")
def enrich_events(req: EnrichRequest) -> dict[str, Any]:
    """이벤트 목록의 외부 IP를 일괄 TI 조회해 반환한다."""
    if not req.events:
        raise HTTPException(status_code=400, detail="events가 비어 있습니다.")
    try:
        enriched = threat_intel_service.enrich_events(req.events)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"TI 보강 실패: {exc}") from exc
    return {"enriched": enriched, "count": len(enriched)}


# ------------------------------------------------------------------ #
# CVE 엔드포인트
# ------------------------------------------------------------------ #

@app.get("/api/cve/recent")
def get_recent_cves(limit: int = 8) -> dict[str, Any]:
    """최근 30일 내 고위험 CVE 목록 (CVSS >= 7.0)."""
    try:
        return {"cves": cve_service.get_recent_cves(limit)}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"CVE 조회 실패: {exc}") from exc


class SignaturesRequest(BaseModel):
    signatures: list[str]


@app.post("/api/cve/by-signatures")
def get_cves_by_signatures(req: SignaturesRequest) -> dict[str, Any]:
    """탐지된 시그니처 목록과 연관된 CVE를 매핑해 반환한다."""
    try:
        return {"mapped": cve_service.get_cves_for_signatures(req.signatures)}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"CVE 매핑 실패: {exc}") from exc


# ------------------------------------------------------------------ #
# Insights 엔드포인트
# ------------------------------------------------------------------ #

@app.get("/api/insights/trends")
def get_trends(days: int = 7) -> dict[str, Any]:
    """기간별 공격 트렌드 통계 및 Gemini 해석."""
    if days not in (7, 14, 30):
        raise HTTPException(status_code=400, detail="days는 7, 14, 30 중 하나여야 합니다.")
    try:
        return insights_service.get_trends(days)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"트렌드 조회 실패: {exc}") from exc


@app.get("/api/insights/summary")
def get_summary() -> dict[str, Any]:
    """주간 위협 요약 (경영진 보고용)."""
    try:
        return insights_service.get_summary()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"요약 생성 실패: {exc}") from exc


# ------------------------------------------------------------------ #
# 내부 헬퍼
# ------------------------------------------------------------------ #

def _format_ti_context(ti_data: dict[str, Any]) -> str:
    """TI 조회 결과를 Gemini 프롬프트용 텍스트로 변환한다."""
    lines = []
    for ip, data in ti_data.items():
        if not data.get("is_malicious"):
            continue
        adb = data.get("sources", {}).get("abuseipdb", {})
        otx = data.get("sources", {}).get("otx", {})
        pulse_str = ""
        if otx.get("pulse_names"):
            pulse_str = f", 캠페인: {', '.join(otx['pulse_names'])}"
        lines.append(
            f"- {ip}: 위험도 {data.get('risk_score', 0)}/100"
            f", 신고 {adb.get('total_reports', '?')}건"
            f", 국가 {adb.get('country_code', '?')}"
            f", ISP {adb.get('isp', '?')}"
            f"{pulse_str}"
        )
    if not lines:
        return ""
    return "[위협 인텔리전스 보강]\n" + "\n".join(lines)


# ------------------------------------------------------------------ #
# 프론트엔드 정적 파일 서빙 (React 빌드 결과물)
# ------------------------------------------------------------------ #
_FRONTEND_BUILD = config.BASE_DIR / "frontend" / "build"

if _FRONTEND_BUILD.exists():
    # /static 경로: JS·CSS·이미지 등 해시된 정적 에셋
    app.mount("/static", StaticFiles(directory=str(_FRONTEND_BUILD / "static")), name="static")

    @app.get("/{full_path:path}", response_class=HTMLResponse, include_in_schema=False)
    def serve_spa(full_path: str) -> HTMLResponse:
        """React SPA — API 경로가 아닌 모든 요청은 index.html로 폴백."""
        index = _FRONTEND_BUILD / "index.html"
        return HTMLResponse(index.read_text(encoding="utf-8"))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=config.APP_HOST, port=config.APP_PORT, reload=True)
