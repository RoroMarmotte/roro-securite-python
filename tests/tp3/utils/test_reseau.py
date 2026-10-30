from tp3.utils.reseau import xor_bytes


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
