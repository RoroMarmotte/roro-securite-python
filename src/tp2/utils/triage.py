SCORE_MAX = 10
POINTS_PAR_REGLE = 2
SEUIL_PACKE = 6.5


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
