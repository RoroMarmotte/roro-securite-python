from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, rdpcap, sniff
from scapy.layers.http import HTTP
from scapy.plist import PacketList

from tp1.utils.config import logger


# Fonction d'ouverture de pcap / lecture d'interface
def capture(interface=None, pcap=None):
    """
    Capture le trafique
    Args:
        interface: via la carte réseaux
        pcap:  via un fichier existant

    renvoie : les paquets trouvé durant la capture sous la forme d'un dictionnaire trié par heure
    """
    if pcap:
        packets = rdpcap(pcap)
        packets = sorted(packets, key=lambda p: p.time)
    elif interface:
        logger.info(f"Capture traffic from interface {interface}")
        packets = sniff(iface=interface, count=15)
    else:
        raise ValueError("Il faut une interface ou un fichier pcap")

    return packets


def sort_network_protocols(packets: PacketList) -> dict:
    """
    Récupère une PacketList obtenue par capture().
    Parcours les paquets un à un et attribue à chacun son protocole le plus précis.
    Retourne un dictionnaire {protocole: nombre de paquets}.
    Commence par http avant de check tcp car http utilise du tcp

    Comptage par couche
    """
    sorted_packets = {
        "HTTP": 0,
        "DNS": 0,
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "ARP": 0,
        "IP": 0,
        "Ethernet": 0,
    }
    for p in packets:
        if p.haslayer(HTTP):
            sorted_packets["HTTP"] += 1
        if p.haslayer(DNS):
            sorted_packets["DNS"] += 1
        if p.haslayer(TCP):
            sorted_packets["TCP"] += 1
        if p.haslayer(UDP):
            sorted_packets["UDP"] += 1
        if p.haslayer(ICMP):
            sorted_packets["ICMP"] += 1
        if p.haslayer(ARP):
            sorted_packets["ARP"] += 1
        if p.haslayer(IP):
            sorted_packets["IP"] += 1
        if p.haslayer(Ether):
            sorted_packets["Ethernet"] += 1
    return sorted_packets
