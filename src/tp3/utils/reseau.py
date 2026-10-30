def xor_bytes(data: bytes, cle: bytes) -> bytes:
    """
    on fait un XOR octet par octet entre les données et la clé (la clé se répète si elle
    est plus courte) ; comme le XOR est réversible, la même fonction encode et décode
    """
    return bytes(octet ^ cle[i % len(cle)] for i, octet in enumerate(data))
