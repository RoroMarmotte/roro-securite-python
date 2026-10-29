SCORE_MAX = 10
POINTS_PAR_REGLE = 2


def calculer_score(yara_matches: list[str], iocs: dict, injection: bool) -> int:
    """
    le score de 0 à 10 se calcule sans l'IA : 2 points par règle yara qui sonne, 1 point
    par type d'IOC trouvé, et 1 point si le fichier essaie de manipuler une IA
    """
    score = POINTS_PAR_REGLE * len(yara_matches)
    for valeurs in iocs.values():
        if valeurs:
            score += 1
    if injection:
        score += 1
    return min(score, SCORE_MAX)