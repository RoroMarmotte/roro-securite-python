from scapy.all import ARP, IP, TCP, Ether, wrpcap
from tp1.utils.capture import capture


def test_capture_lecture_pcap(tmp_path):
    # 2 paquets écrits dans un fichier pcap temporaire
    chemin = tmp_path / "mini.pcap"
    chemin = str(chemin)
    paquets = [Ether() / IP() / TCP(), Ether() / ARP()]
    wrpcap(chemin, paquets)
    resultat = capture(pcap=chemin)
    assert len(resultat) == 2


def test_capture_sans_argument():
    """
    Une lecture sans capture doit renvoyer une erreur
    """
    try:
        capture()
    except ValueError:
        return
    assert False, "capture() aurait dut refuser le manque d'arugment"


def test_capture_ecoute_interface(monkeypatch):
    def faux_sniff(iface, count):
        return ["Ether() / IP() / TCP()"]

    monkeypatch.setattr("tp1.utils.capture.sniff", faux_sniff)

    resultat = capture(interface="eth0", pcap=None)

    assert resultat == ["Ether() / IP() / TCP()"]


def test_capture_trie_les_paquets_par_heure(tmp_path):
    chemin = str(tmp_path / "desordre.pcap")
    premier = Ether() / IP() / TCP()
    second = Ether() / ARP()
    premier.time = 20
    second.time = 15
    wrpcap(chemin, [premier, second])

    resultat = capture(pcap=chemin)

    assert resultat[0].time == 15 and resultat[1].time == 20
