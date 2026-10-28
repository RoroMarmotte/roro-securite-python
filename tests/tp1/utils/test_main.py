import json
from tp1.main import main
from scapy.all import ARP, IP, TCP, Ether, wrpcap


def test_main_ecrit_report_json(tmp_path, monkeypatch):
    """
    test la construction json par le main après l'appel des différentes fonctions
    Args:
        tmp_path: argument par défaut pour la construction d'un chemin temporaire
        monkeypatch: argument par défaut déviation d'une fonction pour un test temporaire
    """
    pcap = str(tmp_path / "mini.pcap")
    sortie = str(tmp_path / "report.json")
    paquets = [
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / IP() / TCP(),
        Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(),
    ]
    wrpcap(pcap, paquets)
    monkeypatch.setattr("sys.argv", ["tp1", "--pcap", pcap, "--out", sortie])
    main()
    with open(sortie, encoding="utf-8") as fichier:
        rapport = json.load(fichier)

    assert rapport["protocols"] == {"TCP": 1, "IP": 1, "ARP": 1, "Ethernet": 2}
    assert rapport["attacks"] == []
    assert rapport["flag"] == ""
