from scapy.all import ARP, IP, TCP, Ether, wrpcap
from tp1.utils.capture import capture


def test_capture_lecture_pcap(tmp_path):
    """
    test de lecture d'un faux fichier pcap qui renvoie le bon nombre de protocole
    Args:
        tmp_path: argument par défaut de pytest
    """
    # 2 paquets écrits dans un fichier pcap temporaire
    chemin = tmp_path / "mini.pcap"
    chemin = str(chemin)
    paquets = [
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / IP() / TCP(),
        Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(),
    ]
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
    """
    Vérifie qu'on puisse écouter sur une interface
    Args:
        monkeypatch: arguments par défaut de pytest pour détourné une fonction
    """

    def faux_sniff(iface, count):
        return ["Ether() / IP() / TCP()"]

    monkeypatch.setattr("tp1.utils.capture.sniff", faux_sniff)

    resultat = capture(interface="eth0", pcap=None)

    assert resultat == ["Ether() / IP() / TCP()"]


def test_capture_trie_les_paquets_par_heure(tmp_path):
    """
    Vérifie que les paquets sont triés par heure (notamment pour les attaques spoofing)
    """
    chemin = str(tmp_path / "desordre.pcap")
    premier = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / IP() / TCP()
    second = Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP()
    premier.time = 20
    second.time = 15
    wrpcap(chemin, [premier, second])

    resultat = capture(pcap=chemin)

    assert resultat[0].time == 15 and resultat[1].time == 20
