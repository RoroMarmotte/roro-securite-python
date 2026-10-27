from tp1.utils.report import build_report


def test_build_report_nettoyer_zero():
    protocols = {"TCP": 3, "ARP": 0}
    resultat = build_report(protocols, [], flag=None)
    assert resultat["protocols"] == {"TCP": 3}


def test_build_report_attaques_et_flag():
    attaques = [{"type": "arp_spoofing", "attacker": "aa:bb:cc:dd:ee:ff"}]
    flag = "ESGI{tentative}"

    resultat = build_report(protocols={"ARP": 1}, attacks=attaques, flag=flag)

    assert resultat["attacks"] == attaques
    assert resultat["flag"] == flag
