from scapy.all import IP, TCP, UDP, ARP, Ether, Raw
from tp1.utils import detection


def test_get_payload_text_decode_url():
    """
    Vérifie qu'on décode correctement le texte du payload notamment les caractère spéciaux
    """
    paquet = Ether() / IP() / TCP() / Raw(b"GET /?id=%27")
    resultat = detection.get_payload_text(paquet)
    assert resultat == "GET /?id='"


def test_get_payload_text_sans_tcp():
    """
    Vérifie qu’un paquet sans couche TCP donne un texte vide
    """
    paquet = Ether() / IP() / UDP()
    resultat = detection.get_payload_text(paquet)
    assert resultat == ""


def test_is_syn():
    """
    Test si la fontion détecte bien les réponses syn et renvoie false s'il y'en a pas
    """
    demande = Ether() / IP() / TCP(flags="S")
    reponse = Ether() / IP() / TCP(flags="SA")
    arp = Ether() / ARP()

    assert detection.is_syn(packet=demande)
    assert not detection.is_syn(packet=reponse)
    assert not detection.is_syn(packet=arp)


def test_detect_port_scan_trouve_scan():
    """
    test si on detecte bien un scan de port et qu'on renvoie correctement la detection
    """
    paquets = []
    for port in range(1, 21):
        paquets.append(Ether() / IP(src="10.0.0.5") / TCP(dport=port, flags="S"))

    resultat = detection.detect_port_scan(paquets)

    assert resultat == [{"type": "port_scan", "attacker": "10.0.0.5"}]


def test_detect_port_scan_peu_de_ports():
    """
    test qu'une ip qui vise seulement 3 ports n'est pas prise pour un scan
    """
    paquets = []
    for port in range(1, 4):
        paquets.append(Ether() / IP(src="10.0.0.5") / TCP(dport=port, flags="S"))

    resultat = detection.detect_port_scan(paquets)

    assert resultat == []


def test_detect_port_scan_ignore_les_syn_ack():
    """
    test que les reponses SYN-ACK du serveur ne sont pas comptees comme un scan
    """
    paquets = []
    for port in range(1, 21):
        paquets.append(Ether() / IP(src="10.0.0.5") / TCP(dport=port, flags="SA"))

    resultat = detection.detect_port_scan(paquets)

    assert resultat == []


def test_is_http_request():
    """
    Vérifie que la fonction is http renvoie bien True lors d'une requête http et False sinon
    """
    assert detection.is_http_request("GET /index.html HTTP/1.1") is True
    assert detection.is_http_request("POST /login HTTP/1.1") is True
    assert detection.is_http_request("HTTP/1.1 200 OK") is False


def test_contains_sql_injection():
    """
    test si la fonction contains sql injection détecte bien les motifs
    """
    assert detection.contains_sql_injection("id=1' OR 1=1") is True
    assert detection.contains_sql_injection("id=1 UNION SELECT password")
    assert not detection.contains_sql_injection("id=42")


def test_detect_sql_injection_encodee():
    """
    test qu'une injection encodee dans l'url (%27, +) est bien detectee
    """
    paquet = Ether() / IP(src="10.0.0.9") / TCP() / Raw(b"GET /?id=1%27+OR+1%3D1 HTTP/1.1")
    resultat = detection.detect_sql_injection([paquet])
    assert resultat == [{"type": "sql_injection", "attacker": "10.0.0.9"}]


def test_detect_sql_injection_requete_normale():
    """
    test qu'une requete http normale n'est pas prise pour une injection
    """
    paquet = Ether() / IP(src="10.0.0.9") / TCP() / Raw(b"GET /index.html HTTP/1.1")
    resultat = detection.detect_sql_injection([paquet])
    assert resultat == []


def test_detect_sql_injection_une_fois_par_ip():
    """
    test qu'un attaquant qui envoie plusieurs injections n'apparait qu'une fois
    """
    paquet = Ether() / IP(src="10.0.0.9") / TCP() / Raw(b"GET /?id=1' OR 1=1 HTTP/1.1")
    resultat = detection.detect_sql_injection([paquet, paquet])
    assert len(resultat) == 1


def test_detect_sql_injection_ignore_les_reponses():
    """
    test que la reponse du serveur qui contient un motif n'est pas prise pour l'attaque
    """
    paquet = Ether() / IP(src="10.0.0.1") / TCP() / Raw(b"HTTP/1.1 200 OK ... UNION SELECT")
    resultat = detection.detect_sql_injection([paquet])
    assert resultat == []


def test_trouver_revendications_arp():
    """
    test que le carnet garde toutes les mac qui revendiquent la même ip
    """
    paquets = [
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="ee:ee:ee:ee:ee:ee"),
    ]
    resultat = detection.trouver_revendications_arp(paquets)

    assert resultat == {"10.0.0.1": {"aa:aa:aa:aa:aa:aa", "ee:ee:ee:ee:ee:ee"}}


def test_trouver_revendications_arp_ignore_les_requetes():
    """
    test qu'une requête arp ne revendique aucune ip
    """
    paquets = [Ether() / ARP(op=1, psrc="10.0.0.2", pdst="10.0.0.1")]
    resultat = detection.trouver_revendications_arp(paquets)

    assert resultat == {}


def test_compter_arp_sans_demande_echange_normal():
    """
    test qu'une réponse arp qui suit une demande n'est pas comptée
    """
    paquets = [
        Ether() / ARP(op=1, psrc="10.0.0.2", pdst="10.0.0.1"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa"),
    ]
    resultat = detection.compter_arp_sans_demande(paquets)
    assert resultat == {}


def test_compter_arp_sans_demande_reponse_seule():
    """
    test qu'une réponse arp sans demande avant est comptée pour sa mac
    """
    paquets = [Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="ee:ee:ee:ee:ee:ee")]
    resultat = detection.compter_arp_sans_demande(paquets)
    assert resultat == {"ee:ee:ee:ee:ee:ee": 1}


def test_detecter_arp_spoofing_trouve_attaquant():
    """
    test que seule la mac de l'attaquant est signalée, pas celle de la vraie machine
    """
    paquets = [
        Ether() / ARP(op=1, psrc="10.0.0.2", pdst="10.0.0.1"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa"),
    ]
    for i in range(3):
        paquets.append(Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="ee:ee:ee:ee:ee:ee"))

    resultat = detection.detecter_arp_spoofing(paquets)
    assert resultat == [{"type": "arp_spoofing", "attacker": "ee:ee:ee:ee:ee:ee"}]


def test_detecter_arp_spoofing_trafic_normal():
    """
    test que des échanges arp normaux ne sont pas pris pour une attaque
    """
    paquets = [
        Ether() / ARP(op=1, psrc="10.0.0.2", pdst="10.0.0.1"),
        Ether() / ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:aa"),
        Ether() / ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.2"),
        Ether() / ARP(op=2, psrc="10.0.0.2", hwsrc="bb:bb:bb:bb:bb:bb"),
    ]
    resultat = detection.detecter_arp_spoofing(paquets)
    assert resultat == []


def test_analyse_regroupe_les_attaques():
    """
    test que analyse renvoie a la fois le scan de ports et l'injection sql
    """
    paquets = []
    for port in range(1, 21):
        paquets.append(Ether() / IP(src="10.0.0.5") / TCP(dport=port, flags="S"))
    paquets.append(Ether() / IP(src="10.0.0.9") / TCP() / Raw(b"GET /?id=1%27+OR+1%3D1 HTTP/1.1"))

    resultat = detection.analyse(paquets)

    assert len(resultat) == 2
    assert {"type": "port_scan", "attacker": "10.0.0.5"} in resultat
    assert {"type": "sql_injection", "attacker": "10.0.0.9"} in resultat


def test_extraire_flag():
    """
    test qu'on recupere le flag avec ses accolades, et "" s'il est absent ou pas ferme
    """
    assert detection.extraire_flag("abc ESGI{toto} def") == "ESGI{toto}"
    assert detection.extraire_flag("rien") == ""
    assert detection.extraire_flag("ESGI{pas fermé") == ""


def test_trouver_attaquants():
    """
    test qu'on recupere les ip et les mac des attaquants, sans doublon
    """
    attaques = [
        {"type": "port_scan", "attacker": "10.0.0.5"},
        {"type": "sql_injection", "attacker": "10.0.0.5"},
        {"type": "arp_spoofing", "attacker": "aa:bb:cc:dd:ee:ff"},
    ]
    resultat = detection.trouver_attaquants(attaques)
    assert resultat == {"10.0.0.5", "aa:bb:cc:dd:ee:ff"}
