from pathlib import Path

CHEMIN_WORDLIST = Path(__file__).parent.parent / "wordlist.txt"


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
