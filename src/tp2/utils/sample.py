from pathlib import Path


def lister_echantillons(dossier: str) -> list[Path]:
    """
    renvoie la liste triée des fichiers du dossier à analyser, sans les sous-dossiers
    """
    echantillons = []
    for chemin in Path(dossier).iterdir():
        if chemin.is_file():
            echantillons.append(chemin)
    return sorted(echantillons)