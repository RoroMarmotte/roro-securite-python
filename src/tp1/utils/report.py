import json


def build_report(protocols, attacks, flag):
    """
    Assemble le rapport final (protocols, attacks, flag) en retirant les protocoles à 0
    """
    protocoles_non_vides = {}
    for nom, nombre in protocols.items():
        if nombre > 0:
            protocoles_non_vides[nom] = nombre
    return {"protocols": protocoles_non_vides, "attacks": attacks, "flag": flag}


def write_json(report, path):
    """
    écrire un fichier json contenant le rapport
    """
    with open(path, "w", encoding="utf-8") as fichier:
        json.dump(report, fichier, indent=2)
