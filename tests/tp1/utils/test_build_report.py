import json

from tp1.utils.report import build_report
from tp1.utils.report import write_json
from tp1.utils.report import save_pdf


def test_build_report_nettoyer_zero():
    """
    test la fonction build_report pour voir si elle nullifie les paquets avec 0 au compteur
    """
    protocols = {"TCP": 3, "ARP": 0}
    resultat = build_report(protocols, [], flag=None)
    assert resultat["protocols"] == {"TCP": 3}


def test_build_report_attaques_et_flag():
    """
    vérifie que la fonction build report renvoie bien le flag et l'attaque si présente
    """
    attaques = [{"type": "arp_spoofing", "attacker": "aa:bb:cc:dd:ee:ff"}]
    flag = "ESGI{tentative}"

    resultat = build_report(protocols={"ARP": 1}, attacks=attaques, flag=flag)

    assert resultat["attacks"] == attaques
    assert resultat["flag"] == flag


def test_write_json_ecrit_le_fichier(tmp_path):
    """
    vérifie que la fonction write_json renvoie un fichier json une fois qu'on l'écrit
    """
    chemin = str(tmp_path / "report.json")
    rapport = {"protocols": {"ARP": 1, "TCP": 1}, "attacks": [], "flag": ""}
    write_json(report=rapport, path=chemin)

    with open(chemin, encoding="utf-8") as fichier:
        relu = json.load(fichier)

    assert rapport == relu


def test_save_pdf_cree_un_pdf(tmp_path):
    """
    test que save_pdf cree bien un vrai fichier pdf
    """
    chemin = str(tmp_path / "report.pdf")
    rapport = {"protocols": {"TCP": 3, "ARP": 1}, "attacks": [], "flag": ""}
    save_pdf(rapport, chemin)
    with open(chemin, "rb") as fichier:
        debut = fichier.read(4)
    assert debut == b"%PDF"
