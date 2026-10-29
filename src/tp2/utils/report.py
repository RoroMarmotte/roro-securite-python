import json
from pathlib import Path


def write_json(resultat: dict, dossier: str) -> Path:
    """
    on écrit le rapport d'un échantillon dans le dossier --out, sous le nom <sha256>.json
    comme le veut la correction, et on crée le dossier s'il existe pas encore
    """
    sortie = Path(dossier)
    sortie.mkdir(parents=True, exist_ok=True)
    chemin = sortie / f"{resultat['sha256']}.json"
    with open(chemin, "w", encoding="utf-8") as fichier:
        json.dump(resultat, fichier, indent=2, ensure_ascii=False)
    return chemin
