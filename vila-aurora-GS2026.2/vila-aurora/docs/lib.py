import json, os, csv
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image, KeepTogether, Preformatted
FD = "/usr/share/fonts/truetype/dejavu/"
pdfmetrics.registerFont(TTFont("DV", FD + "DejaVuSans.ttf")); pdfmetrics.registerFont(TTFont("DVB", FD + "DejaVuSans-Bold.ttf")); pdfmetrics.registerFont(TTFont("DVM", FD + "DejaVuSansMono.ttf"))
pdfmetrics.registerFontFamily("DV", normal="DV", bold="DVB", italic="DV", boldItalic="DVB")
H = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BR = colors.HexColor("#0b5d3b"); GR = colors.HexColor("#eef3f0")
S = {"t": ParagraphStyle("t", fontName="DVB", fontSize=22, leading=27, textColor=BR, spaceAfter=10), "st": ParagraphStyle("st", fontName="DV", fontSize=12, leading=16, textColor=colors.HexColor("#333")),
     "h1": ParagraphStyle("h1", fontName="DVB", fontSize=14, leading=18, textColor=BR, spaceBefore=12, spaceAfter=6), "h2": ParagraphStyle("h2", fontName="DVB", fontSize=11, leading=14, spaceBefore=8, spaceAfter=3),
     "p": ParagraphStyle("p", fontName="DV", fontSize=9, leading=12.5, spaceAfter=4), "c": ParagraphStyle("c", fontName="DV", fontSize=7.6, leading=9.6), "ch": ParagraphStyle("ch", fontName="DVB", fontSize=7.6, leading=9.6, textColor=colors.white),
     "code": ParagraphStyle("code", fontName="DVM", fontSize=7, leading=8.6, backColor=GR, borderPadding=3), "warn": ParagraphStyle("warn", fontName="DV", fontSize=9, leading=12.5, backColor=colors.HexColor("#fff4d6"), borderPadding=5, spaceAfter=6, spaceBefore=4)}
def P(t, s="p"): return Paragraph(t, S[s])
def B(items): return [Paragraph("• " + i, ParagraphStyle("b", parent=S["p"], leftIndent=12, firstLineIndent=-8, spaceAfter=2)) for i in items]
def T(rows, widths, head=True, zebra=True):
    data = [[Paragraph(str(c), S["ch" if (head and i == 0) else "c"]) for c in r] for i, r in enumerate(rows)]
    t = Table(data, colWidths=[w * cm for w in widths], repeatRows=1 if head else 0)
    st = [("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#999")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]
    if head: st.append(("BACKGROUND", (0, 0), (-1, 0), BR))
    if zebra: st += [("BACKGROUND", (0, i), (-1, i), GR) for i in range(2, len(rows), 2)]
    t.setStyle(TableStyle(st)); return t
import textwrap
def code(txt):
    lines = []
    for l in txt.replace("\t", "    ").splitlines(): lines += textwrap.wrap(l, 108, subsequent_indent="    ", break_long_words=True, replace_whitespace=False) or [""]
    return Preformatted("\n".join(lines), S["code"])
def footer(title):
    def f(c, d):
        c.saveState(); c.setFont("DV", 7); c.setFillColor(colors.grey)
        c.drawString(2 * cm, 1.1 * cm, f"FIAP · Global Solution 2026.2 · {title}"); c.drawRightString(A4[0] - 2 * cm, 1.1 * cm, f"Página {d.page}"); c.restoreState()
    return f
def build(path, title, story):
    SimpleDocTemplate(path, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm, topMargin=1.8 * cm, bottomMargin=1.8 * cm, title=title, author="Lorenzo Costa Jordão; Thiago Carrasco de Souza").build(story, onFirstPage=footer(title), onLaterPages=footer(title))
def J(p): return json.load(open(f"{H}/{p}"))
def cover(code_id, title):
    return [Spacer(1, 3 * cm), P("FIAP · GLOBAL SOLUTION 2026.2 · CYBERSECURITY", "st"), Spacer(1, 6), P(title, "t"), P(f"Entregável {code_id} — Rede Comunitária Vila Aurora (Serra Clara/SP, fictícia)", "st"), Spacer(1, 12),
            T([["Integrante", "RM"], ["Lorenzo Costa Jordão", "99819"], ["Thiago Carrasco de Souza", "99571"], ["Turma / Grupo", "[PREENCHER]"]], [8, 5]), Spacer(1, 10),
            P("Professor: Prof. Carlos Eduardo de Siqueira · Data: 17/11/2026 · Todos os dados são sintéticos; toda atividade ofensiva ocorreu somente no ambiente próprio e isolado da equipe.", "p"), PageBreak()]
