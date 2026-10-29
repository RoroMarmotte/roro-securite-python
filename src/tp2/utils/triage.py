from pathlib import Path

import yara

from tp2.utils.llm import construire_resume, llm_triage
from tp2.utils.sample import (
    extract_iocs,
    extraire_overlay,
    extraire_strings,
    get_file_metadata,
    parse_binary,
    ressemble_a_une_injection,
    trouver_flag,
)
from tp2.utils.scanner import yara_scan

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
    le score de 0 à 10 se calcule sans le llm : 2 points par règle yara qui sonne, 1 point
    par type d'IOC trouvé, 1 point si le fichier a l'air packé et 1 point s'il essaie
    de manipuler un llm
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
    on devine la famille sans le llm : la famille qui a le plus d'indices dans les imports et
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


def est_code_mitre(code) -> bool:
    """
    vérifie qu'un texte est un code MITRE ATT&CK bien formé : T suivi de 4 chiffres,
    avec éventuellement une sous-technique de 3 chiffres (T1071 ou T1059.001)
    """
    if not isinstance(code, str):
        return False
    morceaux = code.split(".")
    technique = morceaux[0]
    if len(technique) != 5 or technique[0] != "T" or not technique[1:].isdigit():
        return False
    if len(morceaux) == 1:
        return True
    if len(morceaux) == 2:
        return len(morceaux[1]) == 3 and morceaux[1].isdigit()
    return False


def fusionner_verdict(score: int, famille: str, mitre: list[str], verdict: dict | None) -> dict:
    """
    combine le verdict de nos règles (score, famille, mitre) avec celui du llm (verdict) :
    le llm peut monter le score mais jamais le baisser, on ne garde de lui que des codes MITRE
    bien formés, et s'il n'a pas répondu on garde juste le verdict de nos règles
    """
    if verdict is None:
        return {
            "family_guess": famille,
            "mitre_attack": mitre,
            "llm_summary": "llm indisponible : verdict de nos règles (yara, IOC, entropie)",
            "score": score,
        }

    techniques = set(mitre)
    for technique in verdict["mitre_attack"]:
        if est_code_mitre(technique):
            techniques.add(technique)

    if famille == "unknown" and isinstance(verdict["famille"], str):
        famille = verdict["famille"]

    capacites = [str(capacite) for capacite in verdict["capacites"]]
    return {
        "family_guess": famille,
        "mitre_attack": sorted(techniques),
        "llm_summary": f"{verdict['famille']} : {', '.join(capacites)}",
        "score": max(score, round(verdict["score_0_10"])),
    }


def analyser_echantillon(chemin: Path, regles: yara.Rules) -> dict:
    """
    analyse un échantillon sans jamais l'exécuter (on lit juste ses octets) et renvoie
    le dictionnaire au format exact attendu par la correction
    """
    data = chemin.read_bytes()
    metadata = get_file_metadata(data)
    overlay = extraire_overlay(data)
    iocs = extract_iocs(overlay)
    imports = parse_binary(str(chemin))["imports"]
    yara_matches = yara_scan(data, regles)
    injection = any(ressemble_a_une_injection(morceau) for morceau in extraire_strings(overlay))

    score = calculer_score(yara_matches, iocs, metadata["entropy"], injection)
    famille = deviner_famille(iocs, imports, yara_matches)
    mitre = deviner_mitre(iocs, imports, yara_matches)
    verdict = llm_triage(construire_resume(metadata, iocs, imports, yara_matches))
    final = fusionner_verdict(score, famille, mitre, verdict)

    return {
        "sha256": metadata["sha256"],
        "md5": metadata["md5"],
        "size": metadata["size"],
        "entropy": metadata["entropy"],
        "file_type": metadata["file_type"],
        "iocs": iocs,
        "imports": imports,
        "yara_matches": yara_matches,
        "family_guess": final["family_guess"],
        "mitre_attack": final["mitre_attack"],
        "llm_summary": final["llm_summary"],
        "score": final["score"],
        "flag": trouver_flag(data),
    }
