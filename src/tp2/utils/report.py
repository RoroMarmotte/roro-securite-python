import json
from pathlib import Path

from fpdf import FPDF


def write_json(resultat: dict, dossier: str) -> Path:
    """
    on écrit le rapport d'un échantillon dans le dossier --out, sous le nom <sha256>.json
    comme le veut la correction, et on crée le dossier s'il existe pas encore
    """
    sortie = Path(dossier)
    sortie.mkdir(parents=True, exist_ok=True)
    chemin = sortie / f"{resultat['sha256']}.json"
    with open(chemin, "w", encoding="utf-8") as fichier:
        json.dump(resultat, fichier, indent=2, ensure_ascii=False)
    return chemin


def generate_report(resultats: list[dict], chemin: str) -> None:
    """
    le PDF pour un humain : un tableau avec une ligne par échantillon (début du sha256,
    famille, score, règles yara et techniques MITRE), lisible en 30 secondes
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Rapport de triage", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"{len(resultats)} échantillon(s) analysé(s)", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    with pdf.table(col_widths=(40, 25, 15, 60, 50)) as tableau:
        tableau.row(["SHA-256", "Famille", "Score", "YARA", "MITRE"])
        for resultat in resultats:
            tableau.row(
                [
                    resultat["sha256"][:16] + "...",
                    resultat["family_guess"],
                    f"{resultat['score']}/10",
                    ", ".join(resultat["yara_matches"]) or "-",
                    ", ".join(resultat["mitre_attack"]) or "-",
                ]
            )
    pdf.output(chemin)
