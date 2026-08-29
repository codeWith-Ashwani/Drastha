from __future__ import annotations

import html
import re
import sys
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    KeepTogether,
    ListFlowable,
    ListItem,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)


NAVY = colors.HexColor("#12233F")
TEAL = colors.HexColor("#00A6A6")
PALE = colors.HexColor("#EAF7F7")
LIGHT = colors.HexColor("#F3F6FA")
MUTED = colors.HexColor("#53657A")


def rich_text(value: str) -> str:
    escaped = html.escape(value)
    escaped = re.sub(r"`([^`]+)`", r'<font name="Courier">\1</font>', escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", escaped)
    return escaped


class WalkthroughDoc(BaseDocTemplate):
    def __init__(self, path: str) -> None:
        super().__init__(
            path,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=20 * mm,
            bottomMargin=18 * mm,
            title="AegisFlow Build Walkthrough - Sprints 0 to 3",
            author="AegisFlow SIH Team",
            subject="Cumulative engineering walkthrough",
        )
        frame = Frame(self.leftMargin, self.bottomMargin, self.width, self.height, id="main")
        self.addPageTemplates(PageTemplate(id="content", frames=frame, onPage=self.decorate_page))

    def decorate_page(self, canvas, doc) -> None:
        canvas.saveState()
        width, height = A4
        if doc.page > 1:
            canvas.setStrokeColor(colors.HexColor("#D9E2EC"))
            canvas.line(18 * mm, height - 13 * mm, width - 18 * mm, height - 13 * mm)
            canvas.setFont("Helvetica-Bold", 8)
            canvas.setFillColor(NAVY)
            canvas.drawString(18 * mm, height - 10 * mm, "AEGISFLOW")
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(MUTED)
            canvas.drawRightString(width - 18 * mm, height - 10 * mm, "SIH Engineering Walkthrough")
        canvas.setStrokeColor(colors.HexColor("#D9E2EC"))
        canvas.line(18 * mm, 12 * mm, width - 18 * mm, 12 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(18 * mm, 8 * mm, "Snapshot: 29 August 2026")
        canvas.drawRightString(width - 18 * mm, 8 * mm, f"Page {doc.page}")
        canvas.restoreState()


def styles():
    base = getSampleStyleSheet()
    return {
        "cover_title": ParagraphStyle(
            "CoverTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=30,
            leading=35, textColor=colors.white, alignment=TA_LEFT, spaceAfter=8 * mm,
        ),
        "cover_subtitle": ParagraphStyle(
            "CoverSubtitle", parent=base["Normal"], fontName="Helvetica", fontSize=15,
            leading=21, textColor=colors.HexColor("#DCEAF4"), alignment=TA_LEFT,
        ),
        "h1": ParagraphStyle(
            "H1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=18,
            leading=23, textColor=NAVY, spaceBefore=7 * mm, spaceAfter=3 * mm,
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=13,
            leading=17, textColor=TEAL, spaceBefore=5 * mm, spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["BodyText"], fontName="Helvetica", fontSize=9.4,
            leading=14, textColor=colors.HexColor("#24364B"), spaceAfter=2.5 * mm,
        ),
        "bullet": ParagraphStyle(
            "Bullet", parent=base["BodyText"], fontName="Helvetica", fontSize=9.2,
            leading=13, textColor=colors.HexColor("#24364B"), leftIndent=3 * mm,
        ),
        "code": ParagraphStyle(
            "Code", parent=base["Code"], fontName="Courier", fontSize=7.5,
            leading=10, textColor=colors.HexColor("#14324A"), leftIndent=3 * mm,
            rightIndent=3 * mm, borderColor=colors.HexColor("#C6E9E9"), borderWidth=0.5,
            borderPadding=6, backColor=PALE, spaceBefore=2 * mm, spaceAfter=3 * mm,
        ),
        "table_header": ParagraphStyle(
            "TableHeader", parent=base["BodyText"], fontName="Helvetica-Bold",
            fontSize=8, leading=10, textColor=colors.white,
        ),
        "table_cell": ParagraphStyle(
            "TableCell", parent=base["BodyText"], fontName="Helvetica", fontSize=7.7,
            leading=10, textColor=colors.HexColor("#24364B"),
        ),
    }


def cover(sty):
    panel = Table(
        [[
            Paragraph("AEGISFLOW", sty["cover_title"]),
        ], [
            Paragraph("Passive AI-Assisted Cyber-Threat Detection", sty["cover_subtitle"]),
        ]],
        colWidths=[174 * mm],
        rowHeights=[50 * mm, 38 * mm],
    )
    panel.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), NAVY),
        ("BOX", (0, 0), (-1, -1), 0, NAVY),
        ("LEFTPADDING", (0, 0), (-1, -1), 12 * mm),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12 * mm),
        ("TOPPADDING", (0, 0), (-1, -1), 10 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8 * mm),
    ]))
    summary = Table(
        [
            ["REPORT", "SIH Engineering Build Walkthrough"],
            ["COVERAGE", "Sprints 0 to 3"],
            ["STATUS", "35 automated tests passing"],
            ["SNAPSHOT", "29 August 2026"],
        ],
        colWidths=[34 * mm, 134 * mm],
    )
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), TEAL),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (1, 0), (1, -1), NAVY),
        ("BACKGROUND", (1, 0), (1, -1), LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D9E2EC")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4 * mm),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4 * mm),
        ("LEFTPADDING", (0, 0), (-1, -1), 4 * mm),
    ]))
    return [Spacer(1, 18 * mm), panel, Spacer(1, 18 * mm), summary, PageBreak()]


def markdown_story(text: str, sty):
    lines = text.splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith("## 1."))
    lines = lines[start:]
    story = []
    paragraph: list[str] = []
    bullets: list[str] = []

    def flush_paragraph():
        if paragraph:
            story.append(Paragraph(rich_text(" ".join(paragraph)), sty["body"]))
            paragraph.clear()

    def flush_bullets():
        if bullets:
            items = [ListItem(Paragraph(rich_text(item), sty["bullet"])) for item in bullets]
            story.append(ListFlowable(items, bulletType="bullet", leftIndent=6 * mm, bulletColor=TEAL))
            story.append(Spacer(1, 2 * mm))
            bullets.clear()

    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("```"):
            flush_paragraph()
            flush_bullets()
            code_lines = []
            index += 1
            while index < len(lines) and not lines[index].startswith("```"):
                code_lines.append(lines[index])
                index += 1
            story.append(Preformatted("\n".join(code_lines), sty["code"]))
        elif line.startswith("## "):
            flush_paragraph()
            flush_bullets()
            story.append(Paragraph(rich_text(line[3:]), sty["h1"]))
        elif line.startswith("### "):
            flush_paragraph()
            flush_bullets()
            story.append(Paragraph(rich_text(line[4:]), sty["h2"]))
        elif line.startswith("- "):
            flush_paragraph()
            bullets.append(line[2:])
        elif line.startswith("|" ):
            flush_paragraph()
            flush_bullets()
            table_lines = []
            while index < len(lines) and lines[index].startswith("|"):
                table_lines.append(lines[index])
                index += 1
            index -= 1
            rows = []
            for table_line in table_lines:
                cells = [cell.strip() for cell in table_line.strip("|").split("|")]
                if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                    continue
                style = sty["table_header"] if not rows else sty["table_cell"]
                rows.append([Paragraph(rich_text(cell), style) for cell in cells])
            widths = [168 * mm / len(rows[0])] * len(rows[0])
            table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("BACKGROUND", (0, 1), (-1, -1), LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#CAD5E2")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 2.5 * mm),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2.5 * mm),
                ("TOPPADDING", (0, 0), (-1, -1), 2.2 * mm),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.2 * mm),
            ]))
            story.extend([table, Spacer(1, 3 * mm)])
        elif not line.strip():
            flush_paragraph()
            flush_bullets()
        else:
            flush_bullets()
            paragraph.append(line.strip())
        index += 1
    flush_paragraph()
    flush_bullets()
    return story


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    source = root / "docs" / "BUILD_WALKTHROUGH.md"
    destination = root / "output" / "pdf" / "AegisFlow_Build_Walkthrough_Latest.pdf"
    destination.parent.mkdir(parents=True, exist_ok=True)
    sty = styles()
    story = cover(sty)
    story.extend(markdown_story(source.read_text(encoding="utf-8"), sty))
    WalkthroughDoc(str(destination)).build(story)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
