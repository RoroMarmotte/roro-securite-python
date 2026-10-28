from scapy.all import IP, TCP, UDP, ARP, Ether, Raw
from tp1.utils.detection import get_payload_text
from tp1.utils.detection import is_syn


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
