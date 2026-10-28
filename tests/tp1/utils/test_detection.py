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
