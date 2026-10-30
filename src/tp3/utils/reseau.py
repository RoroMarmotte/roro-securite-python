import base64
import socket

DELAI = 10


def xor_bytes(data: bytes, cle: bytes) -> bytes:
    """
    on fait un XOR octet par octet entre les données et la clé (la clé se répète si elle
    est plus courte) ; comme le XOR est réversible, la même fonction encode et décode
    """
    return bytes(octet ^ cle[i % len(cle)] for i, octet in enumerate(data))


def phase_reseau(host: str, port: int, cle_hex: str) -> str:
    """
    on se connecte au service TCP : pour chaque jeton reçu (base64 puis XOR avec la clé)
    on renvoie le token décodé, et après les rounds réussis le serveur donne le flag final
    """
    cle = bytes.fromhex(cle_hex)
    with socket.create_connection((host, port), timeout=DELAI) as sock:
        flux = sock.makefile("rwb")
        flux.readline()  # la bannière d'explication, on la saute
        while True:
            ligne = flux.readline()
            if not ligne:
                raise RuntimeError("connexion fermée sans flag")
            texte = ligne.strip()
            if texte.startswith(b"OK "):
                return texte[3:].decode()
            if texte.startswith(b"WRONG") or texte.startswith(b"TIMEOUT"):
                raise RuntimeError("round échoué")
            token = xor_bytes(base64.b64decode(texte), cle)
            flux.write(token + b"\n")
            flux.flush()
