from tp2.main import main


def test_main_cree_le_dossier_de_sortie(tmp_path, monkeypatch):
    """
    test que le main accepte les options du contrat et crée le dossier --out
    """
    echantillons = tmp_path / "samples"
    echantillons.mkdir()
    (echantillons / "a.bin").write_bytes(b"A")
    sortie = tmp_path / "out"
    monkeypatch.setattr(
        "sys.argv",
        ["tp2", "--samples", str(echantillons), "--rules", str(tmp_path), "--out", str(sortie)],
    )

    main()

    assert sortie.is_dir()