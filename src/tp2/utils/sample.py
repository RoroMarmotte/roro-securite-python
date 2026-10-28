import math
from collections import Counter
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


def shannon_entropy(data: bytes) -> float:
    """
    mesure le désordre des octets, de 0 (toujours le même octet) à 8 (octets au hasard, chiffré ou packé)
    """
    if not data:
        return 0.0
    freq = Counter(data)
    n = len(data)
    entropie = -sum((c / n) * math.log2(c / n) for c in freq.values())
    return abs(entropie)
