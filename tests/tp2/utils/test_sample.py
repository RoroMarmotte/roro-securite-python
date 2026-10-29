from tp2.utils.sample import (
    extract_iocs,
    extraire_strings,
    get_file_metadata,
    lister_echantillons,
    ressemble_a_un_domaine,
    shannon_entropy,
)


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


def test_get_file_metadata_sur_abc():
    """
    test avec "abc" parce que ses empreintes sont connues de tout le monde, du coup on sait
    exactement ce qu'on doit trouver
    """
    resultat = get_file_metadata(b"abc")

    assert resultat["sha256"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert resultat["md5"] == "900150983cd24fb0d6963f7d28e17f72"
    assert resultat["size"] == 3
    assert resultat["entropy"] == 1.58
    assert "text" in resultat["file_type"].lower()


def test_extraire_strings_garde_le_texte_lisible():
    """
    test qu'on garde les mots d'au moins 4 caractères et qu'on jette les octets illisibles
    et les mots trop courts
    """
    data = b"\x00\x01abc\x00HELLO\xffworld!!\x00"

    resultat = extraire_strings(data)

    assert resultat == ["HELLO", "world!!"]


def test_ressemble_a_un_domaine_trie_les_faux():
    """
    test qu'un vrai domaine passe, mais pas un nom de fichier ni un bout de hasard
    """
    assert ressemble_a_un_domaine("c2.evil.test") is True
    assert ressemble_a_un_domaine("goat.dll") is False
    assert ressemble_a_un_domaine("CMD.EXE") is False
    assert ressemble_a_un_domaine("7.uu") is False


def test_extract_iocs_trouve_les_bons_indices():
    """
    test sur un faux binaire qui mélange de vrais indices avec des pièges (nom de dll,
    IP impossible, domaine en majuscules) pour voir si on garde que les bons
    """
    data = (
        b"\x00urlmon.dll\x00C2.Evil.Test\x00"
        b"http://c2.evil.test/gate.php\x00"
        b"10.0.0.5\x00999.1.1.1\x00"
        b"Global\\mutex42\x00"
        b"HKCU\\Software\\Run\\svc\x00"
    )

    resultat = extract_iocs(data)

    assert resultat == {
        "domains": ["c2.evil.test"],
        "ips": ["10.0.0.5"],
        "urls": ["http://c2.evil.test/gate.php"],
        "mutex": ["Global\\mutex42"],
        "registry": ["HKCU\\Software\\Run\\svc"],
    }
