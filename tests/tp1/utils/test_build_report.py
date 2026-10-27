from tp1.utils.report import build_report


def test_build_report_nettoyer_zero():
    protocols = {"TCP": 3, "ARP": 0}
    resultat = build_report(protocols, [], flag=None)
    assert resultat["protocols"] == {"TCP": 3}
