# TP1 - IDS/IPS maison

Outil en Python (Scapy) qui analyse une capture réseau : il compte les paquets par protocole,
repère des attaques et retrouve le flag envoyé par l'attaquant.
Les résultats sont écrits dans `report.json` et `report.pdf`.

## Installation

```bash
poetry install
```

## Utilisation

Lire un fichier pcap :

```bash
poetry run tp1 --pcap capture.pcap --out report.json --pdf report.pdf
```

Écouter une interface (pour le développement) :

```bash
poetry run tp1 --interface eth0
```

Par défaut, les fichiers de sortie sont `report.json` et `report.pdf`.

## Rapport JSON

```json
{
  "protocols": { "Ethernet": 143, "IP": 123, "TCP": 95, "ARP": 20 },
  "attacks": [
    { "type": "port_scan", "attacker": "10.0.0.5" },
    { "type": "sql_injection", "attacker": "10.0.0.9" },
    { "type": "arp_spoofing", "attacker": "aa:bb:cc:dd:ee:ff" }
  ],
  "flag": "ESGI{...}"
}
```

- `protocols` : nombre de paquets par protocole, couche par couche
  (un paquet DNS compte aussi en UDP, IP et Ethernet). Les protocoles absents ne sont pas affichés.
- `attacks` : attaques trouvées, avec l'IP (ou la MAC pour l'ARP) de l'attaquant.
- `flag` : le flag `ESGI{...}` envoyé par un attaquant détecté, ou `""`.

Le PDF contient le tableau des volumes par protocole et un graphique en barres.

## Protocoles comptés

Ethernet, ARP, IP, TCP, UDP, ICMP, DNS, HTTP.

## Détections

- **Scan de ports** : une IP qui envoie des SYN (sans ACK) vers au moins 15 ports différents.
- **Injection SQL** : une requête HTTP (`GET` / `POST`) qui contient un motif connu
  (`' or 1=1`, `union select`, `'--`…), après décodage de l'URL.
- **ARP spoofing** : une IP revendiquée par plusieurs MAC ; l'attaquant est la MAC
  qui envoie le plus de réponses ARP sans demande.
- **Flag** : le premier `ESGI{...}` envoyé par un attaquant détecté (les autres sont ignorés).

## Limites

- L'injection SQL est détectée par une liste de motifs : une injection écrite autrement peut passer.
- Le seuil du scan de ports (15 ports) est fixe.

## Tests

```bash
poetry run pytest tests/tp1
```
