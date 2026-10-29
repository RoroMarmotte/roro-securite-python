import sys

from tp2.utils.sample import parse_binary


def test_parse_binary_lit_un_vrai_executable():
    """
    test sur l'exécutable python lui-même : c'est un vrai binaire dispo partout, donc lief
    doit y trouver des imports et des sections
    """
    resultat = parse_binary(sys.executable)

    assert len(resultat["imports"]) > 0
    assert len(resultat["sections"]) > 0
    assert resultat["imports"] == sorted(resultat["imports"])


def test_parse_binary_ignore_un_fichier_texte(tmp_path):
    """
    test qu'un fichier qui n'est pas un exécutable ne fait pas planter, on récupère juste du vide
    """
    fichier = tmp_path / "note.txt"
    fichier.write_text("pas un binaire du tout")

    resultat = parse_binary(str(fichier))

    assert resultat == {"imports": [], "exports": [], "sections": []}