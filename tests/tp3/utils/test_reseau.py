import base64
import socket
import threading

from tp3.utils.reseau import phase_reseau, xor_bytes


def test_xor_bytes_valeur_connue():
    """
    test sur des octets simples : 0x00^0x0f = 0x0f et 0xff^0x0f = 0xf0
    """
    assert xor_bytes(b"\x00\xff", b"\x0f") == bytes([0x0F, 0xF0])


def test_xor_bytes_est_reversible():
    """
    test que XOR deux fois avec la même clé redonne le message d'origine (c'est ce qui
    nous permet de décoder ce que le serveur a encodé)
    """
    cle = bytes.fromhex("ff193b22")
    message = b"token1234567890a"

    chiffre = xor_bytes(message, cle)

    assert chiffre != message
    assert xor_bytes(chiffre, cle) == message


def _faux_serveur(cle: bytes, flag: str) -> int:
    """lance un faux service TCP sur un port libre et renvoie son numéro de port"""
    serveur = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serveur.bind(("127.0.0.1", 0))
    serveur.listen(1)
    port = serveur.getsockname()[1]

    def servir() -> None:
        conn, _ = serveur.accept()
        flux = conn.makefile("rwb")
        flux.write(b"banniere\n")
        flux.flush()
        token = b"abcdef0123456789"
        flux.write(base64.b64encode(xor_bytes(token, cle)) + b"\n")
        flux.flush()
        if flux.readline().strip() == token:
            flux.write(f"OK {flag}\n".encode())
            flux.flush()
        conn.close()
        serveur.close()

    threading.Thread(target=servir, daemon=True).start()
    return port


def test_phase_reseau_recupere_le_flag_final():
    """
    test avec un faux serveur TCP local : il envoie un jeton encodé (base64 + XOR),
    on doit le décoder, le renvoyer, et récupérer le flag final
    """
    cle = bytes.fromhex("ff193b22")
    port = _faux_serveur(cle, "ESGI{chain_test}")

    resultat = phase_reseau("127.0.0.1", port, "ff193b22")

    assert resultat == "ESGI{chain_test}"
