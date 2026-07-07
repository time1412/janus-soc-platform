# -*- coding: utf-8 -*-
"""이벤트 분석 보고서: Jinja2(HTML) 렌더 → PDF 변환.

렌더러 우선순위: WeasyPrint(설치 시) → Playwright(설치 시) → Edge/Chrome 헤드리스(--print-to-pdf).
Windows 기본 환경에서는 별도 설치 없이 Edge로 렌더된다(Chromium 엔진 = Playwright와 동일).
"""
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

import config
import corr_to_report

_DIR = Path(__file__).parent / "report_templates"
_env = Environment(
    loader=FileSystemLoader(str(_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)

_BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    # Linux (Ubuntu VM)
    "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/opt/google/chrome/chrome",
]


def render_html(ctx: dict) -> str:
    tokens = (_DIR / "report_tokens.css").read_text(encoding="utf-8")
    return _env.get_template("incident_report_template.html").render(tokens_css=tokens, **ctx)


def _find_browser() -> str | None:
    for p in _BROWSERS:
        if Path(p).exists():
            return p
    return (shutil.which("google-chrome") or shutil.which("google-chrome-stable")
            or shutil.which("chromium") or shutil.which("chromium-browser")
            or shutil.which("msedge") or shutil.which("chrome"))


def _chromium_run(browser: str, mode: str, extra: list[str], uri: str, timeout: int = 90) -> None:
    cmd = [browser, mode, "--disable-gpu", "--no-sandbox",
           "--hide-scrollbars", "--force-color-profile=srgb"] + extra + [uri]
    subprocess.run(cmd, capture_output=True, timeout=timeout)


def html_to_pdf(html: str, out_path: Path) -> str:
    """HTML 문자열 → PDF 파일. 사용한 엔진명을 반환."""
    out_path = Path(out_path)
    # 1) WeasyPrint
    try:
        from weasyprint import HTML  # type: ignore
        HTML(string=html, base_url=str(_DIR)).write_pdf(str(out_path))
        if out_path.exists():
            return "weasyprint"
    except Exception:
        pass
    # 2) Edge/Chrome 헤드리스
    browser = _find_browser()
    if browser:
        with tempfile.TemporaryDirectory() as td:
            hp = Path(td) / "report.html"
            hp.write_text(html, encoding="utf-8")
            uri = hp.as_uri()
            extra = [f"--print-to-pdf={out_path}", "--no-pdf-header-footer"]
            for mode in ("--headless=new", "--headless"):
                try:
                    _chromium_run(browser, mode, extra, uri)
                except Exception:
                    continue
                if out_path.exists() and out_path.stat().st_size > 0:
                    return "chromium"
    raise RuntimeError("PDF 렌더러를 찾지 못했습니다 (WeasyPrint/Edge/Chrome 미설치).")


def html_to_png(html: str, out_path: Path, width: int = 760, height: int = 1400) -> bool:
    """검증용: HTML → PNG 스크린샷(Edge/Chrome)."""
    browser = _find_browser()
    if not browser:
        return False
    with tempfile.TemporaryDirectory() as td:
        hp = Path(td) / "report.html"
        hp.write_text(html, encoding="utf-8")
        for mode in ("--headless=new", "--headless"):
            try:
                _chromium_run(browser, mode,
                              [f"--screenshot={out_path}", f"--window-size={width},{height}"],
                              hp.as_uri())
            except Exception:
                continue
            if Path(out_path).exists():
                return True
    return False


def generate_event_report(events: list[dict], title: str | None = None,
                          analysis: str | None = None) -> tuple[Path, str]:
    """이벤트 → 보고서 PDF 생성. (출력경로, 엔진) 반환."""
    ctx = corr_to_report.build_context(events, title=title, analysis=analysis)
    html = render_html(ctx)
    out_dir = Path(config.PDF_OUTPUT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"event_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    engine = html_to_pdf(html, out)
    return out, engine
