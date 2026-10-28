from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether
from scapy.layers.http import HTTP, HTTPRequest

from tp1.utils.capture import sort_network_protocols


def test_sort_network_protocols_unicite_paquet_protocole():
    """
    Vérifie que sort_network_protocols compte chaque couche présente dans les paquets
    un paquet par protocole connu, et un paquet HTTP compte aussi en TCP, IP et Ethernet
    """
    paquets = [
        Ether() / IP() / TCP() / HTTP() / HTTPRequest(),  # HTTP
        Ether() / IP() / UDP() / DNS(),  # DNS
        Ether() / IP() / TCP(),  # TCP
        Ether() / IP() / UDP(),  # UDP
        Ether() / IP() / ICMP(),  # ICMP
        Ether() / ARP(),  # ARP
        Ether() / IP(),  # IP
        Ether(),  # Ethernet
    ]
    resultat = sort_network_protocols(paquets)
    assert resultat == {
        "HTTP": 1,
        "DNS": 1,
        "TCP": 2,
        "UDP": 2,
        "ICMP": 1,
        "ARP": 1,
        "IP": 6,
        "Ethernet": 8,
    }


def test_sort_network_protocols_liste_vide():
    """
    Vérifie qu'une liste vide donne tous les compteurs à 0, sans planter
    """
    paquets = []
    resultat = sort_network_protocols(paquets)
    assert resultat == {
        "HTTP": 0,
        "DNS": 0,
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "ARP": 0,
        "IP": 0,
        "Ethernet": 0,
    }
