from pathlib import Path

import requests

CHEMIN_WORDLIST = Path(__file__).parent.parent / "wordlist.txt"
DELAI = 5


def charger_wordlist(chemin: Path = CHEMIN_WORDLIST) -> list[str]:
    """
    on lit la wordlist embarquée (un mot par ligne), en sautant les lignes vides,
    pour avoir la liste des chemins à tester sur la cible
    """
    mots = []
    for ligne in chemin.read_text(encoding="utf-8").splitlines():
        mot = ligne.strip()
        if mot:
            mots.append(mot)
    return mots


def trouver_endpoint(target: str, mots: list[str]) -> str | None:
    """
    on teste chaque mot de la wordlist sur la cible : le premier chemin qui répond
    autre chose qu'un 404 est la page cachée ; sinon on renvoie None
    """
    for mot in mots:
        url = f"{target.rstrip('/')}/{mot}"
        reponse = requests.get(url, timeout=DELAI)
        if reponse.status_code != 404:
            return mot
    return None
