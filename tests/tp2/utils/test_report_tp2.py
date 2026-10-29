import json

from tp2.utils.report import generate_report, write_json


def test_write_json_nom_fichier(tmp_path):
    """
    test que le fichier porte bien le nom échantillon.triage.json, que le dossier est créé tout seul,
    et qu'en le relisant on retrouve exactement le même rapport, accents compris
    """
    resultat = {"sha256": "ab" * 32, "flag": "ESGI{goggins_test}", "llm_summary": "résumé avec accents"}
    dossier = tmp_path / "out" / "triage"

    chemin = write_json(resultat, str(dossier), "sample1")

    assert chemin == dossier / "sample1.triage.json"
    assert chemin.is_file()
    with open(chemin, encoding="utf-8") as fichier:
        assert json.load(fichier) == resultat
    assert "résumé" in chemin.read_text(encoding="utf-8")


EXEMPLE = {
    "sha256": "ab" * 32,
    "family_guess": "dropper",
    "score": 8,
    "yara_matches": ["Persistance_Cle_Run", "Regle_Goggins"],
    "mitre_attack": ["T1071", "T1547"],
}


def test_generate_report_cree_un_pdf(tmp_path):
    """
    test que le PDF est bien créé avec plusieurs échantillons, même quand un échantillon
    n'a ni règle yara ni technique MITRE (on doit afficher un tiret, pas planter)
    """
    chemin = tmp_path / "triage.pdf"
    sans_rien = EXEMPLE.copy()
    sans_rien["yara_matches"] = []
    sans_rien["mitre_attack"] = []

    generate_report([EXEMPLE, sans_rien], str(chemin))

    assert chemin.read_bytes()[:4] == b"%PDF"


def test_generate_report_sans_echantillon(tmp_path):
    """
    test qu'avec un dossier vide (aucun échantillon), on produit quand même un PDF valide
    """
    chemin = tmp_path / "vide.pdf"

    generate_report([], str(chemin))

    assert chemin.read_bytes()[:4] == b"%PDF"
