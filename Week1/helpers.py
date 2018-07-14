def bxor(b1, b2): # use xor for bytes
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)

def toless(a, b):
    """
    xor two byte strings of different lengths
    :param a:
    :param b:
    :return:
    """
    if len(a) > len(b):
        return zip(a[:len(b)], b)
    else:
        return zip(a, b[:len(a)])


def strxor(a, b):
    """
    xor two byte strings of different lengths
    :param a:
    :param b:
    :return:
    """
    return b"".join(bytes([x ^ y]) for x, y in toless(a, b))

