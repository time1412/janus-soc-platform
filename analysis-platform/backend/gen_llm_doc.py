# -*- coding: utf-8 -*-
"""분석플랫폼에서 LLM이 쓰이는 코드·프롬프트 원본을 PDF 한 부로 정리한다.

대상: gemini_service.py(보고서+어시스턴트) / triage_service.py(정·오탐) /
      insights_service.py(인사이트) + config.py(모델 설정).
실행: .venv\\Scripts\\python.exe gen_llm_doc.py
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
OUT = BASE.parent / "분석플랫폼_LLM_코드_프롬프트_원본.pdf"

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

C_NAVY = colors.HexColor("#0d2137")
C_DARK = colors.HexColor("#1a3a5c")
C_BLUE = colors.HexColor("#2e6ca4")
C_GREY = colors.HexColor("#5a7a94")
C_BODY = colors.HexColor("#1e2d3d")
C_BORDER = colors.HexColor("#b0c8e0")
C_CODEBG = colors.HexColor("#f4f6f8")
C_CODEBD = colors.HexColor("#d0d7de")

# ── 한글 폰트 ──
FN, FB = "Helvetica", "Helvetica-Bold"
for name, path in [("KR", r"C:\Windows\Fonts\malgun.ttf"),
                   ("KR", "/usr/share/fonts/truetype/nanum/NanumGothic.ttf")]:
    if Path(path).exists():
        try:
            pdfmetrics.registerFont(TTFont("KR", path)); FN = "KR"; break
        except Exception:
            pass
for name, path in [("KRB", r"C:\Windows\Fonts\malgunbd.ttf"),
                   ("KRB", "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf")]:
    if Path(path).exists():
        try:
            pdfmetrics.registerFont(TTFont("KRB", path)); FB = "KRB"; break
        except Exception:
            pass
if FN == "KR" and FB == "Helvetica-Bold":
    FB = "KR"

S_TTL = ParagraphStyle("ttl", fontName=FB, fontSize=20, textColor=colors.white, leading=26)
S_TLBL = ParagraphStyle("tlbl", fontName=FN, fontSize=9, textColor=colors.HexColor("#7fb3d3"), leading=13)
S_H1 = ParagraphStyle("h1", fontName=FB, fontSize=13, textColor=C_DARK, leading=18, spaceBefore=4, spaceAfter=2)
S_H2 = ParagraphStyle("h2", fontName=FB, fontSize=10.5, textColor=C_BLUE, leading=15, spaceBefore=6, spaceAfter=2)
S_BODY = ParagraphStyle("body", fontName=FN, fontSize=9.3, textColor=C_BODY, leading=14.5, spaceAfter=3, alignment=TA_LEFT)
S_META = ParagraphStyle("meta", fontName=FN, fontSize=8.5, textColor=C_GREY, leading=12)
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
        indent = len(ln) - len(ln.lstrip(" "))
        pad = " " * (indent + 4)
        cur = ln
        while len(cur) > maxc:
            out.append(cur[:maxc]); cur = pad + cur[maxc:]
        out.append(cur)
    return "\n".join(out)


def code_block(text):
    return Preformatted(wrap_code(text.rstrip()), S_CODE)


def read(name):
    return (BASE / name).read_text(encoding="utf-8")


def between(text, start_sub, end_sub=None):
    lines = text.split("\n")
    s = next(i for i, l in enumerate(lines) if start_sub in l)
    if end_sub is None:
        e = len(lines)
    else:
        e = next((i for i in range(s + 1, len(lines)) if end_sub in lines[i]), len(lines))
    return "\n".join(lines[s:e]).rstrip()


def h1(text):
    return [Spacer(1, 3 * mm),
            HRFlowable(width="100%", thickness=0.6, color=C_BORDER, spaceAfter=2 * mm),
            Paragraph(esc(text), S_H1)]


def h2(text):
    return [Paragraph(esc(text), S_H2)]


def body(text):
    return [Paragraph(text, S_BODY)]


# ── 소스 로드 ──
gemini = read("gemini_service.py")
triage = read("triage_service.py")
insights = read("insights_service.py")

ts = datetime.now().strftime("%Y-%m-%d %H:%M")

story = []

# 표지
cover = Table([[Paragraph("SOC 분석 플랫폼  ·  내부 기술 문서", S_TLBL)],
               [Paragraph("LLM 사용 코드 · 프롬프트 원본 정리", S_TTL)],
               [Paragraph(f"생성 {ts}  ·  OpenRouter(OpenAI 호환) / 모델 gemini-2.5-flash", S_TLBL)]],
              colWidths=[CONTENT_W])
cover.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, -1), C_NAVY),
    ("LEFTPADDING", (0, 0), (-1, -1), 7 * mm), ("RIGHTPADDING", (0, 0), (-1, -1), 7 * mm),
    ("TOPPADDING", (0, 0), (0, 0), 6 * mm), ("BOTTOMPADDING", (0, 2), (0, 2), 6 * mm),
    ("TOPPADDING", (0, 1), (0, 1), 2 * mm), ("BOTTOMPADDING", (0, 1), (0, 1), 2 * mm),
]))
story += [cover, Spacer(1, 5 * mm)]

# 개요
story += h1("0. 개요 — LLM이 쓰이는 곳 (4종)")
story += body("분석플랫폼은 OpenRouter(OpenAI 호환 API)로 동일 모델(<b>gemini-2.5-flash</b>, "
              "config.GEMINI_MODEL)을 호출한다. 호출 구조는 system 프롬프트 + user 메시지의 2-메시지 "
              "방식이며, 정·오탐 판정만 temperature=0(재현성)을 명시한다. 아래 표가 전부의 요약이다.")

ov = [[Paragraph(x, S_META) for x in ["용도", "파일", "system 프롬프트 상수", "temp"]]]
for r in [
    ["정·오탐 자동 판정", "triage_service.py", "_BATCH_SYSTEM_PROMPT\n(=_CRITERIA+_CONFIDENCE_RUBRIC+_OUT_FIELDS)", "0"],
    ["공격분석 보고서/요약카드", "gemini_service.py", "_SYSTEM_PROMPT", "기본"],
    ["로그분석 어시스턴트(챗봇)", "gemini_service.py", "_CHAT_SYSTEM_PROMPT", "기본"],
    ["위협 인사이트(트렌드/요약)", "insights_service.py", "_TRENDS_SYSTEM / _SUMMARY_SYSTEM", "기본"],
]:
    ov.append([Paragraph(c, S_META) for c in r])
ovt = Table(ov, colWidths=[34 * mm, 38 * mm, 84 * mm, CONTENT_W - 156 * mm])
ovt.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), C_DARK), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
]))
story += [ovt, Spacer(1, 2 * mm)]
story += body("공통 모델/키 설정 (config.py) — <b>API 키 값은 환경변수에서 로드되며 본 문서에 포함하지 않음</b>:")
story += [code_block('GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")        # 환경변수 (키 값 미포함)\n'
                     'GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")')]

# 1. triage
story += h1("1. 정·오탐 자동 판정 — triage_service.py")
story += body("IDS/WAF 경보를 정탐/오탐으로 자동 분류한다. 페이로드(URI/본문) 내용을 근거로 판정하며, "
              "신규(미캐시) 그룹의 대표 1건만 LLM에 보낸다(비용 절감). temperature=0.")
story += h2("1-A. 판별 프롬프트 (_CRITERIA / _CONFIDENCE_RUBRIC / _OUT_FIELDS / _BATCH_SYSTEM_PROMPT)")
story += [code_block(between(triage, "# 판별 기준(공통)", "def _decode("))]
story += h2("1-B. LLM 호출·프롬프트 조립·파싱 코드")
story += [code_block(between(triage, "def _alert_block(", "def auto_triage("))]

# 2. gemini (report + chat)
story += h1("2. 공격분석 보고서 + 로그분석 어시스턴트 — gemini_service.py")
story += body("동일 파일에 두 용도가 있다. <b>analyze_incident()</b>는 _SYSTEM_PROMPT로 '탐지 이벤트 요약 카드'를, "
              "<b>chat()</b>은 _CHAT_SYSTEM_PROMPT로 로그 Q&amp;A를 수행한다. 파일 전체를 그대로 싣는다.")
story += [code_block(gemini)]

# 3. insights
story += h1("3. 위협 인사이트 — insights_service.py")
story += body("Splunk 집계 통계를 LLM이 해석한다. get_trends()는 _TRENDS_SYSTEM으로 기간별 트렌드를, "
              "get_summary()는 _SUMMARY_SYSTEM으로 경영진 보고용 주간 요약을 생성한다.")
story += [code_block(insights)]

# 마무리 노트
story += h1("부록 — 참고")
story += body("• 모든 호출은 OpenRouter 엔드포인트 <b>https://openrouter.ai/api/v1/chat/completions</b> 사용. "
              "모델명에 '/'가 없으면 'google/' 접두사를 자동 부착한다(_model_name).")
story += body("• 정·오탐 최종 판정은 LLM 단독이 아니라 결정적 보정과 결합된다: 명백한 공격 구문 보정"
              "(_strong_attack_signal)과 DDoS 볼륨 보정(_flood_volume)이 LLM의 오탐을 정탐으로 되돌린다. "
              "(본 문서는 'LLM 호출' 부분에 집중 — 보정 로직은 triage_service.py 하단 auto_triage 참조)")
story += body("• SOC_MOCK=true이면 실제 LLM 대신 mock_data의 샘플 응답을 반환한다(오프라인/폐쇄망 데모).")


def deco(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(C_BORDER); canvas.setLineWidth(0.4)
    canvas.line(MARGIN, 12 * mm, PAGE_W - MARGIN, 12 * mm)
    canvas.setFont(FN, 7.5); canvas.setFillColor(C_GREY)
    canvas.drawString(MARGIN, 8.5 * mm, "기밀 — SOC 분석 플랫폼 내부 기술 문서 (LLM 코드·프롬프트)")
    canvas.drawRightString(PAGE_W - MARGIN, 8.5 * mm, str(doc.page))
    canvas.restoreState()


doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                        topMargin=15 * mm, bottomMargin=16 * mm,
                        title="분석플랫폼 LLM 코드·프롬프트 원본")
doc.build(story, onFirstPage=deco, onLaterPages=deco)
print("OK ->", OUT)
