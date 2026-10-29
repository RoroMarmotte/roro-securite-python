DEBUT_DONNEES = "<DEBUT_DONNEES>"
FIN_DONNEES = "<FIN_DONNEES>"


def construire_resume(metadata: dict, iocs: dict, imports: list, yara_matches: list) -> str:
    """
    Mise en texte des différentes résultats obtenues par lese fonctions pour le llm
    """
    lignes = []
    for cle, valeur in metadata.items():
        lignes.append(f"{cle} : {valeur}")
    lignes.append(f"yara règles matches : {' , '.join(yara_matches)}")
    lignes.append(DEBUT_DONNEES)

    for type_ioc, valeurs in iocs.items():
        lignes.append(f"{type_ioc} : {' , '.join(valeurs)}")
    lignes.extend(imports)
    lignes.append(FIN_DONNEES)
    resume = "\n".join(lignes)
    return resume
