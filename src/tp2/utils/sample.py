import hashlib
import math
import re
from collections import Counter
from pathlib import Path

import lief
import magic

lief.logging.disable()

EXTENSIONS_FICHIERS = {"dll", "exe", "so", "php", "html", "htm", "txt", "sys", "bin", "dat"}
DOMAINE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL = re.compile(r"https?://[^\s\"'<>]+")
MUTEX = re.compile(r"\b(?:Global|Local)\\[\w.-]+")
REGISTRE = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKEY_[A-Z_]+)\\[^\s\"'<>]+")


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


def ressemble_a_un_domaine(candidat: str) -> bool:
    """
    trie les faux domaines : un nom de fichier genre urlmon.dll n'en est pas un, et un vrai
    domaine a au moins un morceau de 3 lettres, contrairement aux bouts de hasard comme 7.uu
    """
    morceaux = candidat.split(".")
    if morceaux[-1].lower() in EXTENSIONS_FICHIERS:
        return False
    return any(len(morceau) >= 3 for morceau in morceaux)


def extract_iocs(data: bytes) -> dict:
    """
    on fouille le texte lisible du fichier pour sortir les indices utiles : domaines, IP,
    URLs, mutex et clés de registre, sans doublon et triés
    """
    texte = "\n".join(extraire_strings(data))

    domaines = set()
    for candidat in DOMAINE.findall(texte):
        if ressemble_a_un_domaine(candidat):
            domaines.add(candidat.lower())

    ips = set()
    for ip in IPV4.findall(texte):
        if all(int(octet) <= 255 for octet in ip.split(".")):
            ips.add(ip)

    return {
        "domains": sorted(domaines),
        "ips": sorted(ips),
        "urls": sorted(set(URL.findall(texte))),
        "mutex": sorted(set(MUTEX.findall(texte))),
        "registry": sorted(set(REGISTRE.findall(texte))),
    }


def parse_binary(path: str) -> dict:
    """
    on ouvre le binaire avec lief pour voir ce qu'il importe, ce qu'il exporte et ses sections,
    et si c'est pas un exécutable (genre un .txt) on renvoie juste des listes vides
    """
    binaire = lief.parse(path)
    if binaire is None:
        return {"imports": [], "exports": [], "sections": []}

    imports = {fonction.name for fonction in binaire.imported_functions if fonction.name}
    exports = {fonction.name for fonction in binaire.exported_functions if fonction.name}
    sections = []
    for section in binaire.sections:
        if section.name:
            sections.append({"name": section.name, "entropy": round(section.entropy, 2)})

    return {"imports": sorted(imports), "exports": sorted(exports), "sections": sections}


def extraire_overlay(data: bytes) -> bytes:
    """
    l'overlay c'est ce qui est collé après la fin officielle du programme, une cachette
    classique pour les malwares ; si y en a pas, on garde tout le fichier
    """
    binaire = lief.parse(data)
    if binaire is None:
        return data

    overlay = bytes(binaire.overlay)
    if not overlay:
        return data
    return overlay
