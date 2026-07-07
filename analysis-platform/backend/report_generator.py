"""공격 분석 PDF 보고서 생성 — 전문 디자인.

마크다운(**, ###, *, ---) 파싱 → 스타일 렌더링
커버 배너 / 섹션 헤더 / 불릿 / 번호 목록 / 위험도 배지 / 이벤트 테이블
"""
import re
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

import config

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

# ─── 색상 ─────────────────────────────────────────────────────────────────────
C_NAVY   = colors.HexColor("#0d2137")
C_DARK   = colors.HexColor("#1a3a5c")
C_BLUE   = colors.HexColor("#2e6ca4")
C_SKY    = colors.HexColor("#dae8f6")
C_BORDER = colors.HexColor("#b0c8e0")
C_GREY   = colors.HexColor("#5a7a94")
C_BODY   = colors.HexColor("#1e2d3d")
C_BG     = colors.HexColor("#f4f7fb")
C_RED    = colors.HexColor("#b03a2e")
C_ORANGE = colors.HexColor("#b7770d")
C_GREEN  = colors.HexColor("#1e7e44")
C_WHITE  = colors.white

# ─── 폰트 ─────────────────────────────────────────────────────────────────────
_FN: str | None = None
_FB: str | None = None


def _init_fonts() -> None:
    global _FN, _FB
    if _FN is not None:
        return
    _FN = "Helvetica"
    _FB = "Helvetica-Bold"

    def _reg(name: str, candidates: list[str]) -> bool:
        for p in candidates:
            if not Path(p).exists():
                continue
            try:
                pdfmetrics.getFont(name)
                return True
            except KeyError:
                pass
            try:
                pdfmetrics.registerFont(TTFont(name, p))
                return True
            except Exception:
                pass
        return False

    if _reg("KR", [r"C:\Windows\Fonts\malgun.ttf",
                    "/usr/share/fonts/truetype/nanum/NanumGothic.ttf"]):
        _FN = "KR"
    if _reg("KRB", [r"C:\Windows\Fonts\malgunbd.ttf",
                     "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf"]):
        _FB = "KRB"
    elif _FN == "KR":
        _FB = "KR"


# ─── 마크다운 → XML 변환 ───────────────────────────────────────────────────────

def _esc(t: str) -> str:
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _xml(t: str) -> str:
    """**bold** → <b>bold</b>, `code`→강조 모노스페이스, HTML 이스케이프."""
    t = _esc(t)
    t = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', t)
    # 인라인 코드/페이로드 강조: 빨간 모노스페이스로 눈에 띄게
    t = re.sub(r'`([^`]+)`',
               r'<font face="Courier" color="#b03a2e"><b>\1</b></font>', t)
    return t


# ─── 페이지 헤더/푸터 ─────────────────────────────────────────────────────────

def _make_page_decorator(report_title: str):
    def decorator(canvas, doc):
        _init_fonts()
        canvas.saveState()
        p = doc.page
        # 하단 구분선 + 푸터
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.4)
        canvas.line(MARGIN, 14 * mm, PAGE_W - MARGIN, 14 * mm)
        canvas.setFont(_FN, 7.5)
        canvas.setFillColor(C_GREY)
        canvas.drawString(MARGIN, 10 * mm, "기밀 문서 — SOC 분석 플랫폼 내부용")
        canvas.drawRightString(PAGE_W - MARGIN, 10 * mm, str(p))
        # 2페이지 이후 상단 헤더
        if p > 1:
            canvas.setStrokeColor(C_BORDER)
            canvas.line(MARGIN, PAGE_H - 12 * mm, PAGE_W - MARGIN, PAGE_H - 12 * mm)
            canvas.setFont(_FN, 8)
            canvas.setFillColor(C_GREY)
            canvas.drawString(MARGIN, PAGE_H - 9.5 * mm, report_title)
        canvas.restoreState()
    return decorator


# ─── 커버 배너 ─────────────────────────────────────────────────────────────────

def _cover(title: str, ts: str) -> list:
    _init_fonts()
    s_lbl = ParagraphStyle("cv_lbl", fontName=_FN, fontSize=8,
                            textColor=colors.HexColor("#7fb3d3"), leading=12)
    s_ttl = ParagraphStyle("cv_ttl", fontName=_FB, fontSize=18,
                            textColor=C_WHITE, leading=25)
    s_dt  = ParagraphStyle("cv_dt",  fontName=_FN, fontSize=8,
                            textColor=colors.HexColor("#7fb3d3"), leading=13)

    tbl = Table(
        [
            [Paragraph("SOC 분석 플랫폼  ·  이벤트 분석 보고서", s_lbl)],
            [Paragraph(_esc(title), s_ttl)],
            [Paragraph(f"생성 일시  :  {ts}", s_dt)],
        ],
        colWidths=[CONTENT_W],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), C_NAVY),
        ("LEFTPADDING",   (0, 0), (-1, -1), 7 * mm),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 7 * mm),
        ("TOPPADDING",    (0, 0), (0, 0),   5 * mm),
        ("BOTTOMPADDING", (0, 0), (0, 0),   1 * mm),
        ("TOPPADDING",    (0, 1), (0, 1),   2 * mm),
        ("BOTTOMPADDING", (0, 1), (0, 1),   2 * mm),
        ("TOPPADDING",    (0, 2), (0, 2),   1 * mm),
        ("BOTTOMPADDING", (0, 2), (0, 2),   5 * mm),
    ]))
    return [tbl, Spacer(1, 7 * mm)]


# ─── 섹션 헤더 (좌측 컬러 바) ─────────────────────────────────────────────────

def _section_header(text: str, level: int, accent: str | None = None) -> list:
    _init_fonts()
    BAR = 4 * mm
    if accent == "action":      # 권장 조치/대응 — 초록 강조로 눈에 띄게
        bar_col, bg, fc, fs = C_GREEN, colors.HexColor("#e7f4ec"), colors.HexColor("#14532d"), 12
    elif level == 1:
        bar_col, bg, fc, fs = C_DARK, C_SKY, C_DARK, 12
    else:
        bar_col, bg, fc, fs = C_BLUE, colors.white, C_DARK, 11

    s = ParagraphStyle(f"sh{level}", fontName=_FB, fontSize=fs,
                        textColor=fc, leading=fs * 1.45)
    tbl = Table(
        [[Paragraph("", s), Paragraph(_xml(text), s)]],
        colWidths=[BAR, CONTENT_W - BAR],
    )
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, 0), bar_col),
        ("BACKGROUND",    (1, 0), (1, 0), bg),
        ("LEFTPADDING",   (0, 0), (0, 0), 0),
        ("RIGHTPADDING",  (0, 0), (0, 0), 0),
        ("LEFTPADDING",   (1, 0), (1, 0), 4 * mm),
        ("RIGHTPADDING",  (1, 0), (1, 0), 3 * mm),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.4, C_BORDER),
    ]))
    return [Spacer(1, 4 * mm), tbl, Spacer(1, 2.5 * mm)]


# ─── 위험도 배지 ────────────────────────────────────────────────────────────────

def _risk_badge(text: str) -> list:
    _init_fonts()
    low = text.lower()
    if any(w in low for w in ["심각", "critical"]):
        bg = colors.HexColor("#7b241c")
    elif any(w in low for w in ["높음", "high"]):
        bg = C_RED
    elif any(w in low for w in ["중간", "보통", "medium"]):
        bg = C_ORANGE
    else:
        bg = C_GREEN

    s = ParagraphStyle("badge", fontName=_FB, fontSize=11,
                        textColor=C_WHITE, leading=16, alignment=TA_CENTER)
    tbl = Table([[Paragraph(text, s)]], colWidths=[52 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), bg),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
    ]))
    return [Spacer(1, 1 * mm), tbl, Spacer(1, 3 * mm)]


# ─── 분석 텍스트 파싱 ─────────────────────────────────────────────────────────

def _parse_analysis(analysis_text: str) -> list:
    _init_fonts()

    s_body = ParagraphStyle("pb",  fontName=_FN, fontSize=10, textColor=C_BODY, leading=16, spaceAfter=2)
    s_bold = ParagraphStyle("pbl", fontName=_FB, fontSize=10, textColor=C_DARK, leading=16, spaceAfter=2)
    s_meta = ParagraphStyle("pm",  fontName=_FN, fontSize=9,  textColor=C_GREY, leading=13, spaceAfter=1)
    s_b1   = ParagraphStyle("b1",  fontName=_FN, fontSize=9.5, textColor=C_BODY, leading=15,
                             leftIndent=5 * mm, firstLineIndent=-3 * mm, spaceAfter=1)
    s_b2   = ParagraphStyle("b2",  fontName=_FN, fontSize=9,   textColor=C_BODY, leading=14,
                             leftIndent=12 * mm, firstLineIndent=-4 * mm, spaceAfter=1)
    s_num  = ParagraphStyle("pn",  fontName=_FN, fontSize=9.5, textColor=C_BODY, leading=15,
                             leftIndent=6 * mm, firstLineIndent=-5 * mm, spaceAfter=2)

    story = []
    in_code = False
    code_buf: list[str] = []

    for line in analysis_text.split("\n"):
        stripped = line.strip()

        # ``` 코드펜스 — 페이로드/명령 블록을 강조 박스로
        if stripped.startswith("```"):
            if in_code:
                story.extend(_code_box(code_buf))
                code_buf = []
            in_code = not in_code
            continue
        if in_code:
            code_buf.append(line)
            continue

        # 빈 줄
        if not stripped:
            story.append(Spacer(1, 2.5 * mm))
            continue

        # --- 구분선
        if stripped == "---":
            story.append(HRFlowable(width="100%", thickness=0.4,
                                     color=C_BORDER, spaceBefore=1 * mm, spaceAfter=2 * mm))
            continue

        # ### / #### 헤더
        m = re.match(r'^(#{1,4})\s+(.+)$', stripped)
        if m:
            level = len(m.group(1))
            heading = m.group(2)
            # 배너에 이미 표시된 보고서 제목 중복 제거
            if level == 3 and re.search(r'(침해사고|공격).+보고서', heading):
                continue
            accent = "action" if re.search(r'권장|조치|대응|remediat|recommend', heading, re.I) else None
            story.extend(_section_header(heading, level=2 if level >= 4 else 1, accent=accent))
            continue

        # 불릿 (* - )
        m = re.match(r'^(\s*)[*\-]\s+(.+)$', line)
        if m:
            depth = len(m.group(1))
            txt = _xml(m.group(2))
            if depth >= 2:
                story.append(Paragraph(f"&#9702;&#160;&#160;{txt}", s_b2))
            else:
                story.append(Paragraph(f"&#8226;&#160;&#160;{txt}", s_b1))
            continue

        # 번호 목록 (1. 2. ...)
        m = re.match(r'^(\d+)\.\s+(.+)$', stripped)
        if m:
            num, txt = m.group(1), _xml(m.group(2))
            story.append(Paragraph(f"<b>{num}.</b>&#160;&#160;{txt}", s_num))
            continue

        # 인라인 처리
        xml_line = _xml(stripped)

        # 독립 bold 줄 — 위험도 배지 여부 판단
        if re.match(r'^<b>.+</b>$', xml_line):
            inner = re.sub(r'</?b>', '', xml_line)
            low = inner.lower()
            if any(w in low for w in ["높음", "심각", "중간", "낮음", "high", "critical", "medium", "low"]):
                story.extend(_risk_badge(inner))
                continue
            story.append(Paragraph(xml_line, s_bold))
            continue

        # AI 도입부 안내 문구는 작은 글씨로
        if re.match(r'^SOC\s+시니어', stripped):
            story.append(Paragraph(xml_line, s_meta))
            continue

        story.append(Paragraph(xml_line, s_body))

    if code_buf:                       # 닫히지 않은 코드펜스 정리
        story.extend(_code_box(code_buf))
    return story


# ─── 이벤트 테이블 ────────────────────────────────────────────────────────────

def _events_table(events: list) -> Table:
    _init_fonts()

    s_h = ParagraphStyle("eth", fontName=_FB, fontSize=8,   textColor=C_WHITE, leading=11, alignment=TA_CENTER)
    s_c = ParagraphStyle("etc", fontName=_FN, fontSize=7.5, textColor=C_BODY,  leading=11)
    s_sc = ParagraphStyle("esc", fontName=_FN, fontSize=7.5, textColor=C_BODY, leading=11, alignment=TA_CENTER)

    HEADERS  = ["시각",   "출발지 IP", "목적지 IP", "시그니처",  "위험도"]
    COLS     = ["_time", "src_ip",   "dest_ip",  "signature", "severity"]
    WIDTHS   = [46*mm,    24*mm,      24*mm,       60*mm,       16*mm]
    SEV_LABEL = {"3": "HIGH", "2": "MED", "1": "LOW"}
    SEV_BG    = {
        "3": colors.HexColor("#fde8e7"),
        "2": colors.HexColor("#fdf3d0"),
        "1": colors.HexColor("#e2f0e2"),
    }

    data = [[Paragraph(h, s_h) for h in HEADERS]]
    for ev in events:
        row = []
        for c in COLS:
            val = str(ev.get(c, "-"))
            if c == "_time":
                val = val[:19].replace("T", " ") if "T" in val else val[:19]
            elif c == "severity":
                val = SEV_LABEL.get(val, val)
            else:
                val = val[:32]
            style = s_sc if c == "severity" else s_c
            row.append(Paragraph(val, style))
        data.append(row)

    tbl = Table(data, colWidths=WIDTHS, repeatRows=1)

    style_cmds = [
        ("BACKGROUND",    (0, 0), (-1, 0),  C_DARK),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("GRID",          (0, 0), (-1, -1), 0.3, C_BORDER),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING",   (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 4),
    ]
    for i, ev in enumerate(events, 1):
        sev = str(ev.get("severity", "1"))
        bg = SEV_BG.get(sev, (C_BG if i % 2 == 0 else C_WHITE))
        style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))

    tbl.setStyle(TableStyle(style_cmds))
    return tbl


# ─── 핵심 요약 카드 (관제 요원 한눈에) ─────────────────────────────────────────

def _summary_card(events: list) -> list:
    """보고서 최상단 '핵심 요약' 카드 — 위험도·공격유형·출발지/목적지·MITRE·신뢰도."""
    _init_fonts()
    if not events:
        return []
    e = events[0]

    def g(*keys, default="-"):
        for k in keys:
            v = e.get(k)
            if v not in (None, "", []):
                return str(v)
        return default

    sev = max((str(x.get("severity") or "1") for x in events), default="1")
    sev_label = {"3": "고위험", "2": "주의", "1": "낮음"}.get(sev, sev)
    sev_bg = {"3": C_RED, "2": C_ORANGE, "1": C_GREEN}.get(sev, C_GREY)

    src = g("src_ip", "asset")
    if src != "-" and e.get("src_port"):
        src = f"{src}:{e['src_port']}"
    dst = g("dest_ip")
    if dst != "-" and e.get("dest_port"):
        dst = f"{dst}:{e['dest_port']}"
    atype = g("ai_attack_type", "rule_title", "signature")
    sig = g("signature", "rule_title")
    mitre = g("mitre")
    conf = e.get("ai_confidence")
    conf_s = f"{conf}%" if conf not in (None, "", 0, "0") else "-"
    when = g("_time", "Time")[:19].replace("T", " ")
    cnt = len(events)

    title_s = ParagraphStyle("sc_t", fontName=_FB, fontSize=10.5, textColor=C_WHITE, leading=14)
    k_s   = ParagraphStyle("sc_k", fontName=_FB, fontSize=8,   textColor=C_GREY, leading=11)
    v_s   = ParagraphStyle("sc_v", fontName=_FN, fontSize=9.5, textColor=C_BODY, leading=13)
    sev_s = ParagraphStyle("sc_s", fontName=_FB, fontSize=12,  textColor=C_WHITE, leading=15, alignment=TA_CENTER)

    half = CONTENT_W / 2
    kw = 22 * mm
    rows = [
        [Paragraph("핵심 요약  (At-a-glance)", title_s), "", "", ""],
        [Paragraph("위험도", k_s),    Paragraph(sev_label, sev_s),        Paragraph("공격 유형", k_s),     Paragraph(_esc(atype[:42]), v_s)],
        [Paragraph("출발지", k_s),    Paragraph(_esc(src), v_s),          Paragraph("목적지", k_s),        Paragraph(_esc(dst), v_s)],
        [Paragraph("탐지 시각", k_s), Paragraph(_esc(when), v_s),         Paragraph("신뢰도 / 건수", k_s), Paragraph(f"{conf_s} / {cnt}건", v_s)],
        [Paragraph("MITRE", k_s),     Paragraph(_esc(mitre[:26]), v_s),   Paragraph("시그니처", k_s),      Paragraph(_esc(sig[:42]), v_s)],
    ]
    tbl = Table(rows, colWidths=[kw, half - kw, kw, half - kw])
    tbl.setStyle(TableStyle([
        ("SPAN",          (0, 0), (-1, 0)),
        ("BACKGROUND",    (0, 0), (-1, 0), C_NAVY),
        ("BACKGROUND",    (0, 1), (0, -1), C_BG),       # key 열 음영
        ("BACKGROUND",    (2, 1), (2, -1), C_BG),
        ("BACKGROUND",    (1, 1), (1, 1), sev_bg),      # 위험도 값 = 컬러 배지
        ("GRID",          (0, 1), (-1, -1), 0.3, C_BORDER),
        ("BOX",           (0, 0), (-1, -1), 0.6, C_DARK),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return [tbl, Spacer(1, 5 * mm)]


def _code_box(lines: list) -> list:
    """페이로드/코드 블록 — 음영 + 좌측 바 + 모노스페이스로 강조."""
    _init_fonts()
    s = ParagraphStyle("codebox", fontName="Courier", fontSize=8.5, textColor=C_BODY, leading=12)
    body = "<br/>".join(_esc(ln) if ln.strip() else "&#160;" for ln in lines) or "&#160;"
    tbl = Table([[Paragraph(body, s)]], colWidths=[CONTENT_W])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#eef2f7")),
        ("LINEBEFORE",    (0, 0), (-1, -1), 2, C_BLUE),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return [Spacer(1, 1 * mm), tbl, Spacer(1, 2.5 * mm)]


# ─── 메인 진입점 ──────────────────────────────────────────────────────────────

def generate_report(
    title: str,
    analysis_text: str,
    events: list[dict] | None = None,
) -> Path:
    _init_fonts()
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fname = f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    out = config.PDF_OUTPUT_DIR / fname

    doc = SimpleDocTemplate(
        str(out),
        pagesize=A4,
        title=title,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=15 * mm,
        bottomMargin=22 * mm,
    )

    story: list = []
    story.extend(_cover(title, ts))
    story.extend(_summary_card(events or []))     # 핵심 요약 카드(한눈에)
    story.extend(_parse_analysis(analysis_text))

    if events:
        story.append(Spacer(1, 8 * mm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
        story.append(Spacer(1, 4 * mm))

        s_app = ParagraphStyle("app", fontName=_FB, fontSize=11, textColor=C_DARK, leading=16)
        s_sub = ParagraphStyle("aps", fontName=_FN, fontSize=8.5, textColor=C_GREY, leading=13)
        story.append(Paragraph("부록 — 원본 탐지 이벤트", s_app))
        story.append(Paragraph(f"상위 {min(len(events), 10)}건 (최신순)", s_sub))
        story.append(Spacer(1, 3 * mm))
        story.append(_events_table(events[:10]))

    page_decorator = _make_page_decorator(title)
    doc.build(story, onFirstPage=page_decorator, onLaterPages=page_decorator)
    return out
