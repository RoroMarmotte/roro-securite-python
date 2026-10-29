import sys
from pathlib import Path

from tp2.utils.sample import extraire_overlay, parse_binary


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


def test_extraire_overlay_recupere_la_zone_cachee():
    """
    test en collant un message à la fin de l'exécutable python : on doit le retrouver
    dans l'overlay, et l'overlay doit être plus petit que le fichier entier
    """
    data = Path(sys.executable).read_bytes() + b"ZONE_CACHEE_GOGGINS"

    resultat = extraire_overlay(data)

    assert resultat.endswith(b"ZONE_CACHEE_GOGGINS")
    assert len(resultat) < len(data)


def test_extraire_overlay_garde_tout_si_pas_un_binaire():
    """
    test que pour du texte (pas un exécutable), on récupère le contenu en entier
    """
    data = b"juste une note, pas un programme"

    assert extraire_overlay(data) == data
