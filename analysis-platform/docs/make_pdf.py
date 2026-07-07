"""마크다운 정의서 → PDF 렌더 (reportlab + 맑은 고딕). 한글 지원.

실행:  python make_pdf.py [입력.md] [출력.pdf]
기본:  프롬프트_엔지니어링_정의서.md → 프롬프트_엔지니어링_정의서.pdf
"""
import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

HERE = Path(__file__).resolve().parent
SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "프롬프트_엔지니어링_정의서.md"
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else HERE / "프롬프트_엔지니어링_정의서.pdf"

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

# 폰트
pdfmetrics.registerFont(TTFont("KR", r"C:\Windows\Fonts\malgun.ttf"))
pdfmetrics.registerFont(TTFont("KRB", r"C:\Windows\Fonts\malgunbd.ttf"))

C_NAVY = colors.HexColor("#0d2137")
C_BLUE = colors.HexColor("#2e6ca4")
C_SKY = colors.HexColor("#e8f0f8")
C_BORDER = colors.HexColor("#c2d3e3")
C_CODE_BG = colors.HexColor("#f3f5f8")
C_BODY = colors.HexColor("#1e2d3d")
C_GREY = colors.HexColor("#5a7a94")

S_H1 = ParagraphStyle("H1", fontName="KRB", fontSize=20, textColor=C_NAVY, spaceAfter=4, leading=26)
S_SUB = ParagraphStyle("SUB", fontName="KR", fontSize=12, textColor=C_BLUE, spaceAfter=10, leading=16)
S_H2 = ParagraphStyle("H2", fontName="KRB", fontSize=14, textColor=C_NAVY, spaceBefore=14, spaceAfter=6, leading=19)
S_H3 = ParagraphStyle("H3", fontName="KRB", fontSize=11.5, textColor=C_BLUE, spaceBefore=9, spaceAfter=4, leading=16)
S_BODY = ParagraphStyle("B", fontName="KR", fontSize=9.5, textColor=C_BODY, leading=15, spaceAfter=4)
S_BULLET = ParagraphStyle("BU", parent=S_BODY, leftIndent=12, bulletIndent=2, spaceAfter=2)
S_CODE = ParagraphStyle("CODE", fontName="KR", fontSize=8.5, textColor=C_BODY, leading=13)
S_TH = ParagraphStyle("TH", fontName="KRB", fontSize=9, textColor=colors.white, leading=13)
S_TD = ParagraphStyle("TD", fontName="KR", fontSize=9, textColor=C_BODY, leading=13)


def inline(s: str) -> str:
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`([^`]+)`", r"\1", s)
    return s


def code_para(lines: list[str]) -> Table:
    body = "<br/>".join(
        (ln.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace(" ", "&nbsp;")) or "&nbsp;"
        for ln in lines
    )
    p = Paragraph(body, S_CODE)
    t = Table([[p]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_CODE_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, C_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def make_table(rows: list[list[str]]) -> Table:
    ncols = max(len(r) for r in rows)
    data = []
    for i, r in enumerate(rows):
        r = r + [""] * (ncols - len(r))
        style = S_TH if i == 0 else S_TD
        data.append([Paragraph(inline(c), style) for c in r])
    t = Table(data, colWidths=[CONTENT_W / ncols] * ncols, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), C_BLUE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C_SKY]),
        ("GRID", (0, 0), (-1, -1), 0.4, C_BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def build(md: str) -> list:
    flow = []
    lines = md.split("\n")
    i = 0
    while i < len(lines):
        ln = lines[i]
        # 코드블록
        if ln.strip().startswith("```"):
            i += 1
            buf = []
            while i < len(lines) and not lines[i].strip().startswith("```"):
                buf.append(lines[i]); i += 1
            i += 1
            flow.append(code_para(buf)); flow.append(Spacer(1, 6))
            continue
        # 테이블
        if ln.lstrip().startswith("|"):
            tbl = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                row = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not re.match(r"^[\s:\-]+$", "".join(row)):  # 구분선 제외
                    tbl.append(row)
                i += 1
            if tbl:
                flow.append(make_table(tbl)); flow.append(Spacer(1, 8))
            continue
        # 구분선
        if ln.strip() == "---":
            flow.append(Spacer(1, 4)); flow.append(HRFlowable(width="100%", thickness=0.6, color=C_BORDER)); flow.append(Spacer(1, 4)); i += 1; continue
        # 헤딩
        if ln.startswith("### "):
            flow.append(Paragraph(inline(ln[4:]), S_H3))
        elif ln.startswith("## "):
            flow.append(Paragraph(inline(ln[3:]), S_H2))
        elif ln.startswith("# "):
            flow.append(Paragraph(inline(ln[2:]), S_H1))
        elif re.match(r"^\s*-\s+", ln):
            txt = re.sub(r"^\s*-\s+", "", ln)
            flow.append(Paragraph("• " + inline(txt), S_BULLET))
        elif re.match(r"^\s*\d+\.\s+", ln):
            flow.append(Paragraph(inline(ln.strip()), S_BULLET))
        elif ln.strip() == "":
            flow.append(Spacer(1, 4))
        else:
            flow.append(Paragraph(inline(ln), S_BODY))
        i += 1
    return flow


def main() -> None:
    md = SRC.read_text(encoding="utf-8")
    doc = SimpleDocTemplate(str(OUT), pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
                            topMargin=MARGIN, bottomMargin=MARGIN, title=SRC.stem)
    doc.build(build(md))
    print(f"PDF 생성: {OUT}  ({round(OUT.stat().st_size/1024)}KB)")


if __name__ == "__main__":
    main()
