from scapy.all import IP, TCP, UDP, ARP, Ether, Raw
from tp1.utils.detection import get_payload_text
from tp1.utils.detection import is_syn, detect_port_scan


def test_get_payload_text_decode_url():
    """
    Vérifie qu'on décode correctement le texte du payload notamment les caractère spéciaux
    """
    paquet = Ether() / IP() / TCP() / Raw(b"GET /?id=%27")
    resultat = get_payload_text(paquet)
    assert resultat == "GET /?id='"


def test_get_payload_text_sans_tcp():
    """
    Vérifie qu’un paquet sans couche TCP donne un texte vide
    """
    paquet = Ether() / IP() / UDP()
    resultat = get_payload_text(paquet)
    assert resultat == ""


def test_is_syn():
    """
    Test si la fontion détecte bien les réponses syn et renvoie false s'il y'en a pas
    """
    demande = Ether() / IP() / TCP(flags="S")
    reponse = Ether() / IP() / TCP(flags="SA")
    arp = Ether() / ARP()

    assert is_syn(packet=demande)
    assert not is_syn(packet=reponse)
    assert not is_syn(packet=arp)


def test_detect_port_scan_trouve_scan():
    """
    test si on detecte bien un scan de port et qu'on renvoie correctement la detection
    """
    paquets = []
    for port in range(1, 21):
        paquets.append(Ether() / IP(src="10.0.0.5") / TCP(dport=port, flags="S"))

    resultat = detect_port_scan(paquets)

    assert resultat == [{"type": "port_scan", "attacker": "10.0.0.5"}]


def test_detect_port_scan_peu_de_ports():
    """
    test qu'une ip qui vise seulement 3 ports n'est pas prise pour un scan
    """
    paquets = []
    for port in range(1, 4):
        paquets.append(Ether() / IP(src="10.0.0.5") / TCP(dport=port, flags="S"))

    resultat = detect_port_scan(paquets)

    assert resultat == []


def test_detect_port_scan_ignore_les_syn_ack():
    """
    test que les reponses SYN-ACK du serveur ne sont pas comptees comme un scan
    """
    paquets = []
    for port in range(1, 21):
        paquets.append(Ether() / IP(src="10.0.0.5") / TCP(dport=port, flags="SA"))

    resultat = detect_port_scan(paquets)

    assert resultat == []
