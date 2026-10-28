from tp2.utils.sample import lister_echantillons, shannon_entropy


def test_lister_echantillons_trie_et_ignore_les_dossiers(tmp_path):
    """
    test que seuls les fichiers sont gardés, triés par nom, sans les sous-dossiers
    """
    (tmp_path / "b.bin").write_bytes(b"B")
    (tmp_path / "a.bin").write_bytes(b"A")
    (tmp_path / "sous_dossier").mkdir()

    resultat = lister_echantillons(str(tmp_path))

    assert resultat == [tmp_path / "a.bin", tmp_path / "b.bin"]


def test_shannon_entropy_valeurs_connues():
    """
    test l'entropie sur des cas dont on connaît le résultat exact
    """
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"AAAA") == 0.0
    assert shannon_entropy(b"AB") == 1.0
    assert shannon_entropy(bytes(range(256))) == 8.0
