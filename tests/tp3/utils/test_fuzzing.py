from tp3.utils import fuzzing


def test_charger_wordlist_ignore_les_lignes_vides(tmp_path):
    """
    test qu'on lit bien un mot par ligne et qu'on saute les lignes vides
    """
    fichier = tmp_path / "wl.txt"
    fichier.write_text("admin\n\ninternal-panel\n")

    assert fuzzing.charger_wordlist(fichier) == ["admin", "internal-panel"]
