from urllib.parse import unquote_plus
from scapy.all import IP, TCP, ARP

SEUIL_SCAN = 15
MOTIFS_SQL = ["' or 1=1", "' or '1'='1", "union select", "'--"]


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


def contains_sql_injection(text):
    """
    tente de détecter par motifs s'il y'a une injection sql dans un texte
    """
    texte = text.lower()
    for motif in MOTIFS_SQL:
        if motif in texte:
            return True
    return False


def detect_sql_injection(packets):
    """
    permet de détecter s'il y'a une injection sql dans une liste de paquets
    """
    attaques = []
    deja_signalees = set()

    for p in packets:
        if not p.haslayer(IP):
            continue
        texte = get_payload_text(p)
        if is_http_request(texte) and contains_sql_injection(texte):
            ip = p[IP].src
            if ip not in deja_signalees:
                attaques.append({"type": "sql_injection", "attacker": ip})
                deja_signalees.add(ip)
    return attaques


def trouver_revendications_arp(packets):
    """
    construit le carnet des réponses arp : pour chaque ip, les mac qui disent la posséder
    """
    carnet = {}
    for p in packets:
        if p.haslayer(ARP) and p[ARP].op == 2:
            ip = p[ARP].psrc
            mac = p[ARP].hwsrc
            if ip not in carnet:
                carnet[ip] = set()
            carnet[ip].add(mac)
    return carnet


def compter_arp_sans_demande(packets):
    """
    compte pour chaque mac le nombre de réponses arp envoyées sans demande avant
    """
    demandes = set()
    sans_demande = {}
    for p in packets:
        if not p.haslayer(ARP):
            continue
        if p[ARP].op == 1:
            demandes.add(p[ARP].pdst)
        elif p[ARP].op == 2:
            ip = p[ARP].psrc
            mac = p[ARP].hwsrc
            if ip in demandes:
                demandes.remove(ip)
            else:
                if mac not in sans_demande:
                    sans_demande[mac] = 0
                sans_demande[mac] += 1
    return sans_demande
