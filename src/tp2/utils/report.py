import json
from pathlib import Path

from fpdf import FPDF


def write_json(resultat: dict, dossier: str, nom: str) -> Path:
    """
    on écrit le rapport d'un échantillon dans le dossier --out, sous le nom <échantillon>.triage.json
    comme le veut la correction (nom = nom du fichier sans son extension), et on crée le dossier
    s'il existe pas encore
    """
    sortie = Path(dossier)
    sortie.mkdir(parents=True, exist_ok=True)
    chemin = sortie / f"{nom}.triage.json"
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
    pdf.cell(0, 10, "Rapport de triage", align="C")
    pdf.ln(12)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"{len(resultats)} échantillon(s) analysé(s)")
    pdf.ln(12)

    largeurs = [40, 25, 15, 60, 50]
    entetes = ["SHA-256", "Famille", "Score", "YARA", "MITRE"]
    pdf.set_font("Helvetica", "B", 10)
    for i in range(len(entetes)):
        pdf.cell(largeurs[i], 8, entetes[i], border=1)
    pdf.ln(8)

    pdf.set_font("Helvetica", "", 9)
    for resultat in resultats:
        yara = ", ".join(resultat["yara_matches"])
        mitre = ", ".join(resultat["mitre_attack"])
        if yara == "":
            yara = "-"
        if mitre == "":
            mitre = "-"
        ligne = [
            resultat["sha256"][:16] + "...",
            resultat["family_guess"],
            f"{resultat['score']}/10",
            yara,
            mitre,
        ]
        for i in range(len(ligne)):
            pdf.cell(largeurs[i], 8, ligne[i], border=1)
        pdf.ln(8)
    pdf.output(chemin)
