import json

from tp1.utils.report import build_report
from tp1.utils.report import write_json


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


def test_write_json_ecrit_le_fichier(tmp_path):
    chemin = str(tmp_path / "report.json")
    rapport = {"protocols": {"ARP": 1, "TCP": 1}, "attacks": [], "flag": ""}
    write_json(report=rapport, path=chemin)

    with open(chemin, encoding="utf-8") as fichier:
        relu = json.load(fichier)

    assert rapport == relu
