from urllib.parse import unquote_plus
from scapy.all import IP, TCP

SEUIL_SCAN = 15


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


def detect_port_scan(packets):
    """
    Si une ip essaie de cartographier les ports alors l'ajouter au carnet
    """
    ports_par_ip = {}

    for p in packets:
        if is_syn(p) and p.haslayer(IP):
            ip = p[IP].src
            port = p[TCP].dport
            if ip not in ports_par_ip:
                ports_par_ip[ip] = set()
            ports_par_ip[ip].add(port)

    attaques = []
    for ip, ports in ports_par_ip.items():
        if len(ports) >= SEUIL_SCAN:
            attaques.append({"type": "port_scan", "attacker": ip})
    return attaques


def is_http_request(text):
    """
    vérifier si on a une requête http grâce à l'entête
    """
    if text.startswith("GET "):
        return True
    elif text.startswith("POST "):
        return True
    else:
        return False
