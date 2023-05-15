import hashlib


def sha3(message):
    hashedMessage = hashlib.sha3_256(message.encode("latin-1")).hexdigest()
    return hashedMessage
