import hashlib
import math
import re
from collections import Counter
from pathlib import Path

import magic


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


def get_file_metadata(data: bytes) -> dict:
    """
    calcule les empreintes, la taille, le type et l'entropie du fichier, sans jamais l'exécuter
    """
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "size": len(data),
        "file_type": magic.from_buffer(data),
        "entropy": round(shannon_entropy(data), 2),
    }


def extraire_strings(data: bytes) -> list[str]:
    """
    comme la commande strings sous Linux : on récupère tous les bouts de texte lisible
    du binaire, d'au moins 4 caractères d'affilée
    """
    morceaux = re.findall(rb"[\x20-\x7e]{4,}", data)
    return [morceau.decode("ascii") for morceau in morceaux]
