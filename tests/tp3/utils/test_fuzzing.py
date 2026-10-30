from tp3.utils import fuzzing


class FausseReponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def test_charger_wordlist_ignore_les_lignes_vides(tmp_path):
    """
    test qu'on lit bien un mot par ligne et qu'on saute les lignes vides
    """
    fichier = tmp_path / "wl.txt"
    fichier.write_text("admin\n\ninternal-panel\n")

    assert fuzzing.charger_wordlist(fichier) == ["admin", "internal-panel"]


def test_trouver_endpoint_retourne_le_premier_non_404(monkeypatch):
    """
    test qu'on garde le premier chemin qui ne répond pas 404 : ici 'cache' répond 200,
    'admin' et 'login' sont des 404 qu'on doit sauter
    """
    reponses = {"admin": 404, "login": 404, "cache": 200}
    monkeypatch.setattr(
        fuzzing.requests, "get", lambda url, timeout: FausseReponse(reponses[url.rsplit("/", 1)[1]])
    )

    resultat = fuzzing.trouver_endpoint("http://cible", ["admin", "login", "cache"])

    assert resultat == "cache"


def test_trouver_endpoint_rien_trouve(monkeypatch):
    """
    test que si tout répond 404, on renvoie None au lieu d'inventer un chemin
    """
    monkeypatch.setattr(fuzzing.requests, "get", lambda url, timeout: FausseReponse(404))

    assert fuzzing.trouver_endpoint("http://cible", ["admin", "login"]) is None
