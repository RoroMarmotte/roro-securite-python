# Sécurité Python — TP1 / TP2 / TP3

Projet de binôme pour le cours de sécurité Python (Master 1, ESGI). Trois outils en
ligne de commande, chacun lancé avec Poetry.

## Installation

```
poetry install
```

Le TP2 utilise un LLM via OpenRouter : mettre la clé dans un fichier `.env` à la racine
(`OPENROUTER_API_KEY=...`). Sans réseau, le TP2 utilise un verdict de repli basé sur nos
propres règles. Le TP3 a besoin de l'outil Tesseract installé sur la machine (OCR).

## TP1 — IDS/IPS avec Scapy

Lit un fichier pcap, compte les protocoles par couche, détecte le scan de ports,
l'injection SQL et l'ARP spoofing, cherche le flag, et génère un rapport JSON et PDF.

```
poetry run tp1 --pcap FICHIER.pcap --out report.json
```

## TP2 — Triage de malware

Pour chaque échantillon d'un dossier : empreintes (SHA-256, MD5), taille, type, entropie,
IOC (domaines, IP, URLs, mutex, registre), règles YARA, verdict (score, famille, MITRE
ATT&CK) et flag. Écrit un JSON par échantillon plus un rapport PDF.

```
poetry run tp2 --samples DOSSIER --rules DOSSIER --out DOSSIER
```

## TP3 — Exploit « Breach the target »

Enchaîne une phase web (fuzzing de l'endpoint caché puis résolution du CAPTCHA par OCR)
et une phase réseau (décodage base64 + XOR chronométré) pour récupérer les deux drapeaux.

```
poetry run tp3 --target http://localhost:8080
```

## Tests

```
poetry run pytest tests -v
```

## Qualité

Formatage et lint via pre-commit (ruff, ruff-format). Installation des hooks :

```
pre-commit install
```
