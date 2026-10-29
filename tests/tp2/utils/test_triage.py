from tp2.utils.triage import calculer_score, deviner_famille, deviner_mitre

IOCS_VIDES = {"domains": [], "ips": [], "urls": [], "mutex": [], "registry": []}


def test_calculer_score_sans_aucun_indice():
    """
    test qu'un fichier où on trouve rien du tout a un score de 0
    """
    assert calculer_score([], IOCS_VIDES, 4.0, False) == 0


def test_calculer_score_ne_depasse_jamais_10():
    """
    test qu'un fichier qui coche toutes les cases reste bloqué à 10 :
    5 règles (10) + 2 types d'IOC (2) + packé (1) + injection (1) = 14, ramené à 10
    """
    iocs = {"domains": ["c2.goggins.test"], "ips": ["10.0.0.5"], "urls": [], "mutex": [], "registry": []}

    assert calculer_score(["A", "B", "C", "D", "E"], iocs, 7.9, True) == 10


def test_calculer_score_injection_fait_monter():
    """
    test qu'un fichier qui essaie de manipuler l'IA est plus suspect, pas déclaré sain :
    1 règle (2) + 2 types d'IOC (2) = 4, et 5 avec l'injection
    """
    iocs = {
        "domains": ["c2.goggins.test"],
        "ips": [],
        "urls": ["http://c2.goggins.test/gate.php"],
        "mutex": [],
        "registry": [],
    }

    sans_injection = calculer_score(["Regle_Test"], iocs, 4.8, False)
    avec_injection = calculer_score(["Regle_Test"], iocs, 4.8, True)

    assert sans_injection == 4
    assert avec_injection == 5


def test_deviner_famille_reconnait_chaque_famille():
    """
    test un cas par famille : chaque groupe d'API typiques doit donner la bonne famille,
    et sans API on retombe sur packé (si la règle a sonné) ou trojan (s'il contacte un serveur)
    """
    avec_url = {**IOCS_VIDES, "urls": ["http://c2.goggins.test/gate.php"]}

    assert deviner_famille(IOCS_VIDES, ["URLDownloadToFileA", "CreateProcessA"], []) == "dropper"
    assert deviner_famille(IOCS_VIDES, ["WSASocketA", "connect"], []) == "backdoor"
    assert deviner_famille(IOCS_VIDES, ["SetWindowsHookExA"], []) == "keylogger"
    assert deviner_famille(IOCS_VIDES, ["CryptEncrypt"], []) == "ransomware"
    assert deviner_famille(IOCS_VIDES, ["CryptUnprotectData"], []) == "stealer"
    assert deviner_famille(IOCS_VIDES, [], ["Contenu_Packe"]) == "packed"
    assert deviner_famille(avec_url, [], []) == "trojan"


def test_deviner_famille_inconnue():
    """
    test qu'un fichier sans aucun indice est classé unknown, on invente pas de famille
    """
    assert deviner_famille(IOCS_VIDES, ["printf", "malloc"], []) == "unknown"


def test_deviner_mitre_chaque_technique():
    """
    test que chaque technique est déclenchée par son propre indice, et seulement par lui
    """
    avec_run = {**IOCS_VIDES, "registry": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc"]}
    avec_url = {**IOCS_VIDES, "urls": ["http://c2.goggins.test/gate.php"]}

    assert deviner_mitre(avec_run, [], []) == ["T1547"]
    assert deviner_mitre(avec_url, [], []) == ["T1071"]
    assert deviner_mitre(IOCS_VIDES, [], ["Contenu_Packe"]) == ["T1027"]
    assert deviner_mitre(IOCS_VIDES, ["SetWindowsHookExA"], []) == ["T1056"]
    assert deviner_mitre(IOCS_VIDES, ["cmd.exe"], []) == ["T1059"]
    assert deviner_mitre(IOCS_VIDES, ["URLDownloadToFileA"], []) == ["T1105"]


def test_deviner_mitre_trie_et_liste_vide():
    """
    test que plusieurs techniques sortent triées sans doublon, et qu'un fichier banal
    donne une liste vide
    """
    avec_url = {**IOCS_VIDES, "urls": ["http://c2.goggins.test/gate.php"]}

    assert deviner_mitre(avec_url, ["URLDownloadToFileA"], ["Persistance_Cle_Run"]) == ["T1071", "T1105", "T1547"]
    assert deviner_mitre(IOCS_VIDES, ["printf"], []) == []
