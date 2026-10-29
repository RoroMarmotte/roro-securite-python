import json

from tp2.main import main


def test_main_json_par_echantillon(tmp_path, monkeypatch):
    """
    test que le main lit les options du contrat, analyse chaque échantillon et écrit
    échantillon.triage.json dans --out, sans appeler le vrai llm
    """
    echantillons = tmp_path / "samples"
    echantillons.mkdir()
    (echantillons / "a.bin").write_bytes(b"connexion vers http://c2.exemple.test/gate.php")
    sortie = tmp_path / "out"
    pdf = tmp_path / "rapport.pdf"

    def faux_llm_triage(summary):
        return None

    monkeypatch.setattr("tp2.utils.triage.llm_triage", faux_llm_triage)
    monkeypatch.setattr(
        "sys.argv",
        [
            "tp2",
            "--samples",
            str(echantillons),
            "--rules",
            str(tmp_path),
            "--out",
            str(sortie),
            "--pdf",
            str(pdf),
        ],
    )

    main()

    fichier = sortie / "a.triage.json"
    assert fichier.is_file()
    with open(fichier, encoding="utf-8") as f:
        rapport = json.load(f)
    assert rapport["iocs"]["urls"] == ["http://c2.exemple.test/gate.php"]
    assert pdf.is_file()
    assert list(sortie.iterdir()) == [fichier]
