import json
from fpdf import FPDF


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


def save_pdf(report, path):
    """
    crée un rapport pdf avec un titre et le tableau des protocoles (nom, nombre de paquets)
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

    pdf.output(path)
