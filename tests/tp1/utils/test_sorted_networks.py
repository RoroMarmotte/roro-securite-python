from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, Raw
from scapy.layers.http import HTTP, HTTPRequest

from tp1.utils.capture import sort_network_protocols


def test_sort_network_protocols_unicite_paquet_protocole():
    paquets = [
        Ether() / IP() / TCP() / HTTP() / HTTPRequest(),  # HTTP
        Ether() / IP() / UDP() / DNS(),  # DNS
        Ether() / IP() / TCP(),  # TCP
        Ether() / IP() / UDP(),  # UDP
        Ether() / IP() / ICMP(),  # ICMP
        Ether() / ARP(),  # ARP
        Ether() / IP(),  # IP
        Ether(),  # Ethernet
        Raw(b"x"),  # Other
    ]
    resultat = sort_network_protocols(paquets)
    assert resultat == {
        "HTTP": 1,
        "DNS": 1,
        "TCP": 1,
        "UDP": 1,
        "ICMP": 1,
        "ARP": 1,
        "IP": 1,
        "Ethernet": 1,
        "Other": 1,
    }
