import json
from tp1.main import main
from scapy.all import ARP, IP, TCP, Ether, wrpcap


def test_main_ecrit_report_json(tmp_path, monkeypatch):
    pcap = str(tmp_path / "mini.pcap")
    sortie = str(tmp_path / "report.json")
    paquets = [Ether() / IP() / TCP(), Ether() / ARP()]
    wrpcap(pcap, paquets)
    monkeypatch.setattr("sys.argv", ["tp1", "--pcap", pcap, "--out", sortie])
    main()
    with open(sortie, encoding="utf-8") as fichier:
        rapport = json.load(fichier)

    assert rapport["protocols"] == {"TCP": 1, "ARP": 1}
    assert rapport["attacks"] == []
    assert rapport["flag"] == ""
