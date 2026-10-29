SCORE_MAX = 10
POINTS_PAR_REGLE = 2
SEUIL_PACKE = 6.5
REGLE_PACKE = "Contenu_Packe"
INDICES_FAMILLES = {
    "dropper": ["urldownloadtofile", "urlmon.dll", "winexec", "createprocess"],
    "backdoor": ["wsasocket", "ws2_32.dll", "cmd.exe"],
    "keylogger": ["setwindowshookex", "getasynckeystate"],
    "ransomware": ["cryptencrypt", "cryptgenkey"],
    "stealer": ["cryptunprotectdata", "credenumerate"],
}
REGLE_PERSISTANCE = "Persistance_Cle_Run"
INDICES_MITRE = {
    "T1056": ["setwindowshookex", "getasynckeystate"],
    "T1059": ["cmd.exe", "powershell"],
    "T1105": ["urldownloadtofile"],
}


def calculer_score(yara_matches: list[str], iocs: dict, entropie: float, injection: bool) -> int:
    """
    le score de 0 à 10 se calcule sans l'IA : 2 points par règle yara qui sonne, 1 point
    par type d'IOC trouvé, 1 point si le fichier a l'air packé et 1 point s'il essaie
    de manipuler une IA
    """
    score = POINTS_PAR_REGLE * len(yara_matches)
    for valeurs in iocs.values():
        if valeurs:
            score += 1
    if entropie >= SEUIL_PACKE:
        score += 1
    if injection:
        score += 1
    return min(score, SCORE_MAX)


def deviner_famille(iocs: dict, imports: list[str], yara_matches: list[str]) -> str:
    """
    on devine la famille sans l'IA : la famille qui a le plus d'indices dans les imports et
    les règles gagne ; sinon packé si notre règle a sonné, trojan s'il contacte un serveur,
    et unknown si on trouve vraiment rien
    """
    indices = " ".join(imports + yara_matches).lower()
    meilleure = "unknown"
    meilleur_total = 0
    for famille, mots in INDICES_FAMILLES.items():
        total = sum(1 for mot in mots if mot in indices)
        if total > meilleur_total:
            meilleure = famille
            meilleur_total = total

    if meilleure != "unknown":
        return meilleure
    if REGLE_PACKE in yara_matches:
        return "packed"
    if iocs["domains"] or iocs["ips"] or iocs["urls"]:
        return "trojan"
    return "unknown"


def deviner_mitre(iocs: dict, imports: list[str], yara_matches: list[str]) -> list[str]:
    """
    on traduit ce qu'on a trouvé en techniques MITRE ATT&CK, genre une clé Run ça donne
    T1547 (persistance), une URL T1071 (il parle à un serveur) et un fichier packé T1027
    """
    techniques = set()
    cle_run = any("\\run" in cle.lower() for cle in iocs["registry"])
    if cle_run or REGLE_PERSISTANCE in yara_matches:
        techniques.add("T1547")
    if iocs["urls"]:
        techniques.add("T1071")
    if REGLE_PACKE in yara_matches:
        techniques.add("T1027")

    texte = " ".join(imports).lower()
    for technique, mots in INDICES_MITRE.items():
        if any(mot in texte for mot in mots):
            techniques.add(technique)
    return sorted(techniques)
