from tp2.utils.triage import calculer_score


def test_calculer_score_additionne_les_indices():
    """
    test du calcul : 1 règle yara (2 pts) + 2 types d'IOC (2 pts) + une injection (1 pt) = 5
    """
    iocs = {
        "domains": ["c2.goggins.test"],
        "ips": [],
        "urls": ["http://c2.goggins.test/gate.php"],
        "mutex": [],
        "registry": [],
    }

    assert calculer_score(["Regle_Test"], iocs, True) == 5


def test_calculer_score_sain_et_plafond():
    """
    test qu'un fichier sans rien donne 0, et qu'un fichier qui coche tout reste bloqué à 10
    """
    iocs_vides = {"domains": [], "ips": [], "urls": [], "mutex": [], "registry": []}
    iocs_pleins = {"domains": ["a.test"], "ips": ["10.0.0.5"], "urls": [], "mutex": [], "registry": []}

    assert calculer_score([], iocs_vides, False) == 0
    assert calculer_score(["A", "B", "C", "D", "E"], iocs_pleins, True) == 10
