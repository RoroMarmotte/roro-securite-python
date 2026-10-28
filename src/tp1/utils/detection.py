from urllib.parse import unquote_plus
from scapy.all import TCP


def get_payload_text(packet):
    """
    Récupère le payload dans un paquet
    """
    if not packet.haslayer(TCP):
        return ""

    contenu = bytes(packet[TCP].payload)
    texte = contenu.decode("utf-8", errors="ignore")
    return unquote_plus(texte)


def is_syn(packet):
    """
    si le packet est un syn et non un ack renvoie True sinon false
    """
    if not packet.haslayer(TCP):
        return False

    flags = packet[TCP].flags
    if flags.S and not flags.A:
        return True
    else:
        return False
