# -*- coding: utf-8 -*-
"""SIEM 상관탐지 연동에서 '수정/신규된 프롬프트·코드'만 모아 PDF로 정리한다.

대상 변경분:
  config.py        — 상관 notable 수신 설정(NOTABLE_SPL / ALERT_SOURCE)
  splunk_client.py — 상관 notable 수신·매핑(recent_alerts 분기 / recent_notables / _map_notable)
  triage_service.py— 상관 전용 프롬프트 + 근거 펼침 + 상관 분류기 + auto_triage 라우팅 + 가드레일
실행: .venv\\Scripts\\python.exe gen_corr_doc.py
"""
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle,
)

BASE = Path(__file__).resolve().parent
OUT = BASE.parent / "분석플랫폼_상관탐지_수정_프롬프트_코드.pdf"

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

C_NAVY = colors.HexColor("#0d2137"); C_DARK = colors.HexColor("#1a3a5c")
C_BLUE = colors.HexColor("#2e6ca4"); C_GREY = colors.HexColor("#5a7a94")
C_BODY = colors.HexColor("#1e2d3d"); C_BORDER = colors.HexColor("#b0c8e0")
C_CODEBG = colors.HexColor("#f4f6f8"); C_CODEBD = colors.HexColor("#d0d7de")

FN, FB = "Helvetica", "Helvetica-Bold"
for path in (r"C:\Windows\Fonts\malgun.ttf", "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"):
    if Path(path).exists():
        try:
            pdfmetrics.registerFont(TTFont("KR", path)); FN = "KR"; break
        except Exception:
            pass
for path in (r"C:\Windows\Fonts\malgunbd.ttf", "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf"):
    if Path(path).exists():
        try:
            pdfmetrics.registerFont(TTFont("KRB", path)); FB = "KRB"; break
        except Exception:
            pass
if FN == "KR" and FB == "Helvetica-Bold":
    FB = "KR"

S_TTL = ParagraphStyle("ttl", fontName=FB, fontSize=19, textColor=colors.white, leading=25)
S_TLBL = ParagraphStyle("tlbl", fontName=FN, fontSize=9, textColor=colors.HexColor("#7fb3d3"), leading=13)
S_H1 = ParagraphStyle("h1", fontName=FB, fontSize=13, textColor=C_DARK, leading=18, spaceBefore=4, spaceAfter=2)
S_H2 = ParagraphStyle("h2", fontName=FB, fontSize=10.5, textColor=C_BLUE, leading=15, spaceBefore=6, spaceAfter=2)
S_BODY = ParagraphStyle("body", fontName=FN, fontSize=9.3, textColor=C_BODY, leading=14.5, spaceAfter=3, alignment=TA_LEFT)
S_CODE = ParagraphStyle("code", fontName=FN, fontSize=7.4, leading=10.2, textColor=C_BODY,
                        backColor=C_CODEBG, borderColor=C_CODEBD, borderWidth=0.5, borderPadding=5,
                        spaceBefore=2, spaceAfter=9)


def esc(t):
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def wrap_code(text, maxc=108):
    out = []
    for ln in text.split("\n"):
        if len(ln) <= maxc:
            out.append(ln); continue
        pad = " " * (len(ln) - len(ln.lstrip(" ")) + 4)
        cur = ln
        while len(cur) > maxc:
            out.append(cur[:maxc]); cur = pad + cur[maxc:]
        out.append(cur)
    return "\n".join(out)


def code_block(text):
    return Preformatted(wrap_code((text or "").rstrip()), S_CODE)


def read(name):
    return (BASE / name).read_text(encoding="utf-8")


def between(text, start_sub, end_sub=None, maxlines=400):
    lines = text.split("\n")
    s = next((i for i, l in enumerate(lines) if start_sub in l), None)
    if s is None:
        return f"(섹션 '{start_sub}' 미발견)"
    if end_sub is None:
        e = len(lines)
    else:
        e = next((i for i in range(s + 1, len(lines)) if end_sub in lines[i]), None)
        if e is None:
            e = min(len(lines), s + maxlines)
    return "\n".join(lines[s:e]).rstrip()


def h1(t):
    return [Spacer(1, 3 * mm), HRFlowable(width="100%", thickness=0.6, color=C_BORDER, spaceAfter=2 * mm),
            Paragraph(esc(t), S_H1)]


def h2(t):
    return [Paragraph(esc(t), S_H2)]


def body(t):
    return [Paragraph(t, S_BODY)]


config = read("config.py")
splunk = read("splunk_client.py")
triage = read("triage_service.py")
ts = datetime.now().strftime("%Y-%m-%d %H:%M")

story = []
cover = Table([[Paragraph("SOC 분석 플랫폼  ·  내부 기술 문서", S_TLBL)],
               [Paragraph("SIEM 상관탐지 연동 — 수정·신규 프롬프트·코드", S_TTL)],
               [Paragraph(f"생성 {ts}  ·  soc_notable_json 수신 + 근거(evidence) 기반 상관 판정", S_TLBL)]],
              colWidths=[CONTENT_W])
cover.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
    ("LEFTPADDING", (0, 0), (-1, -1), 7 * mm), ("RIGHTPADDING", (0, 0), (-1, -1), 7 * mm),
    ("TOPPADDING", (0, 0), (0, 0), 6 * mm), ("BOTTOMPADDING", (0, 2), (0, 2), 6 * mm),
    ("TOPPADDING", (0, 1), (0, 1), 2 * mm), ("BOTTOMPADDING", (0, 1), (0, 1), 2 * mm),
]))
story += [cover, Spacer(1, 4 * mm)]

story += h1("0. 변경 요약")
story += body("분석플랫폼이 단일 장비 alert(soc_base) 대신 <b>SIEM 상관탐지(soc_notable_json)</b>를 1차 알림으로 "
              "수신하도록 바꾸고, 상관 이벤트는 <b>기여 이벤트(evidence) 기반 전용 LLM 판정 경로</b>로 태우도록 "
              "추가했다. 아래는 수정/신규된 부분만 발췌한 것이다(전체 파일 아님).")
story += body("① config.py — 상관 수신 설정  ② splunk_client.py — 수신·매핑  "
              "③ triage_service.py — 상관 프롬프트·분류기·라우팅·가드레일")

# 1. config
story += h1("1. config.py — 상관 notable 수신 설정 (신규)")
story += body("CORR-005/006(table형)은 sourcetype이 달라 자동 제외된다. SOC_ALERT_SOURCE=socbase로 되돌릴 수 있다.")
story += [code_block(between(config, "# --- SIEM 상관(notable) 수신 ---", "# --- 저장소 ---", maxlines=18))]

# 2. splunk_client
story += h1("2. splunk_client.py — 상관 notable 수신·매핑 (신규/수정)")
story += body("recent_alerts가 ALERT_SOURCE에 따라 분기하고, recent_notables가 JSON _raw를 파싱해 _map_notable로 "
              "플랫폼 알림 스키마에 매핑한다(대표 근거 페이로드를 uri/body로 펼치고, detection_class·evidence 등 동봉).")
story += h2("2-A. JSON notable → 알림 스키마 매핑 (_first_ip / _map_notable)")
story += [code_block(between(splunk, "def _first_ip(", "class SplunkClient:"))]
story += h2("2-B. 수신 분기 + recent_notables")
story += [code_block(between(splunk, "    def recent_alerts(", "    def alert_summary("))]

# 3. triage
story += h1("3. triage_service.py — 상관 판정 (신규/수정)")
story += h2("3-A. 상관 전용 프롬프트 (_CORR_CRITERIA / _CORR_SYSTEM_PROMPT)")
story += [code_block(between(triage, "# ── 상관탐지(SIEM notable) 전용 판별 기준 ──", "def _decode("))]
story += h2("3-B. 기여 이벤트 펼침 + 상관 프롬프트 빌더 (_evidence_block / _build_corr_prompt)")
story += [code_block(between(triage, "def _evidence_block(", "def _extract_json("))]
story += h2("3-C. 상관 전용 분류기 (classify_correlation_batch)")
story += [code_block(between(triage, "    def classify_correlation_batch(", "    def auto_triage("))]
story += h2("3-D. auto_triage 라우팅 — detection_class별 분류기 분기")
story += [code_block(between(triage, "# 2) 캐시에 없는 신규 그룹만", "# 3) 그룹당 1행으로"))]
story += h2("3-E. 상관탐지 가드레일 (근거 기반 오탐 존중, '심각'만 자동 폐기 방지)")
story += [code_block(between(triage, "# 상관탐지 안전망:", 'results.append({"alert": rep, "triage": triage})'))]

story += h1("부록 — 동작 요약")
story += body("• 수신: index=soc_notable_json sourcetype=\"soc:notable:json\"의 JSON 상관탐지만 수신(table형 CORR-005/006 제외).")
story += body("• 판정 라우팅: detection_class=\"correlation\" → 상관 분류기(룰 의미+근거+요약), 그 외 → 기존 페이로드 분류기.")
story += body("• 가드레일: 근거 기반 오탐은 존중. 단 위험도 '심각' 상관탐지는 AI가 오탐해도 정탐 유지(사람 검토).")
story += body("• 모델: gemini-2.5-flash(OpenRouter). 페이로드 판정 temperature=0. 되돌리기: SOC_ALERT_SOURCE=socbase.")


def deco(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(C_BORDER); canvas.setLineWidth(0.4)
    canvas.line(MARGIN, 12 * mm, PAGE_W - MARGIN, 12 * mm)
    canvas.setFont(FN, 7.5); canvas.setFillColor(C_GREY)
    canvas.drawString(MARGIN, 8.5 * mm, "기밀 — SOC 분석 플랫폼 / SIEM 상관탐지 연동 수정분")
    canvas.drawRightString(PAGE_W - MARGIN, 8.5 * mm, str(doc.page))
    canvas.restoreState()


SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                  topMargin=15 * mm, bottomMargin=16 * mm,
                  title="상관탐지 연동 수정 프롬프트·코드").build(
    story, onFirstPage=deco, onLaterPages=deco)
print("OK ->", OUT)
