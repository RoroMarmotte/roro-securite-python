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
