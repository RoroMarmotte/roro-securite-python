import json
from fpdf import FPDF

LARGEUR_MAX_BARRE = 150


def build_report(protocols, attacks, flag):
    """
    Assemble le rapport final (protocols, attacks, flag) en retirant les protocoles à 0
    """
    protocoles_non_vides = {}
    for nom, nombre in protocols.items():
        if nombre > 0:
            protocoles_non_vides[nom] = nombre
    return {"protocols": protocoles_non_vides, "attacks": attacks, "flag": flag}


def write_json(report, path):
    """
    écrire un fichier json contenant le rapport
    """
    with open(path, "w", encoding="utf-8") as fichier:
        json.dump(report, fichier, indent=2)


def draw_bar_chart(pdf, protocols):
    """
    dessine une barre horizontale par protocole, de longueur proportionnelle à son nombre de paquets
    """
    if not protocols:
        return
    maximum = max(protocols.values())
    pdf.set_fill_color(42, 120, 214)
    for nom, nombre in protocols.items():
        y = pdf.get_y()
        largeur = LARGEUR_MAX_BARRE * nombre / maximum
        pdf.cell(30, 8, nom)
        pdf.rect(pdf.l_margin + 30, y + 1, largeur, 6, style="F")
        pdf.ln(8)


def save_pdf(report, path):
    """
    crée un rapport pdf : titre, tableau et graphique des protocoles, attaques détectées et flag
    """
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Rapport d'analyse réseau", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(5)

    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(60, 8, "Protocole", border=1)
    pdf.cell(40, 8, "Paquets", border=1, new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 12)
    for nom, nombre in report["protocols"].items():
        pdf.cell(60, 8, nom, border=1)
        pdf.cell(40, 8, str(nombre), border=1, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Graphique", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 12)
    draw_bar_chart(pdf, report["protocols"])

    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Attaques détectées", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 12)
    if not report["attacks"]:
        pdf.cell(0, 8, "Aucune attaque détectée", new_x="LMARGIN", new_y="NEXT")
    for attaque in report["attacks"]:
        pdf.cell(0, 8, f"- {attaque['type']} : {attaque['attacker']}", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Flag", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 12)
    if report["flag"]:
        texte_flag = report["flag"]
    else:
        texte_flag = "Aucun flag trouvé"
    pdf.cell(0, 8, texte_flag, new_x="LMARGIN", new_y="NEXT")

    pdf.output(path)
