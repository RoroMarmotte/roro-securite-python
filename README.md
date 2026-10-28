# TP1 - IDS/IPS maison

Outil en Python (Scapy) qui lit une capture réseau, compte les paquets par protocole
et cherche des attaques dedans. Le résultat est écrit dans un fichier `report.json`.

## Installation

```bash
poetry install
```

## Utilisation

Lire un fichier pcap :

```bash
poetry run tp1 --pcap capture.pcap --out report.json
```

Écouter une interface (pour le développement) :

```bash
poetry run tp1 --interface eth0 --out report.json
```

## Contenu du rapport

```json
{
  "protocols": { "Ethernet": 143, "IP": 123, "TCP": 95, "ARP": 20 },
  "attacks": [],
  "flag": ""
}
```

- `protocols` : nombre de paquets par protocole, couche par couche
  (un paquet DNS compte aussi en UDP, IP et Ethernet). Les protocoles absents ne sont pas affichés.
- `attacks` : liste des attaques trouvées, avec leur type et l'adresse de l'attaquant.
- `flag` : le flag `ESGI{...}` envoyé par un attaquant.

## Protocoles comptés

Ethernet, ARP, IP, TCP, UDP, ICMP, DNS, HTTP.

## Détections

- [ ] Scan de ports
- [ ] Injection SQL
- [ ] ARP spoofing
- [ ] Recherche du flag

## Tests

```bash
poetry run pytest tests/tp1
```
