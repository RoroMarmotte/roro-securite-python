import json

from tp2.utils.report import write_json


def test_write_json_ecrit_sha256_point_json(tmp_path):
    """
    test que le fichier porte bien le nom <sha256>.json, que le dossier est créé tout seul,
    et qu'en le relisant on retrouve exactement le même rapport, accents compris
    """
    resultat = {"sha256": "ab" * 32, "flag": "ESGI{goggins_test}", "llm_summary": "résumé avec accents"}
    dossier = tmp_path / "out" / "triage"

    chemin = write_json(resultat, str(dossier))

    assert chemin == dossier / f"{'ab' * 32}.json"
    assert chemin.is_file()
    with open(chemin, encoding="utf-8") as fichier:
        assert json.load(fichier) == resultat
    assert "résumé" in chemin.read_text(encoding="utf-8")
