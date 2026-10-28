from tp2.utils.sample import lister_echantillons


def test_lister_echantillons_trie_et_ignore_les_dossiers(tmp_path):
    """
    test que seuls les fichiers sont gardés, triés par nom, sans les sous-dossiers
    """
    (tmp_path / "b.bin").write_bytes(b"B")
    (tmp_path / "a.bin").write_bytes(b"A")
    (tmp_path / "sous_dossier").mkdir()

    resultat = lister_echantillons(str(tmp_path))

    assert resultat == [tmp_path / "a.bin", tmp_path / "b.bin"]