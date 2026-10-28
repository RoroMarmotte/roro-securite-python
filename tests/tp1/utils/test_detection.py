from scapy.all import IP, TCP, UDP, Ether, Raw
from tp1.utils.detection import get_payload_text


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
