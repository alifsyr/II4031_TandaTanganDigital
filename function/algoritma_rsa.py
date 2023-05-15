import random
import math
from tkinter import messagebox

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def extendedgcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        gcd, x, y = extendedgcd(b % a, a)
        return (gcd, y - (b // a) * x, x)

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime_number():
    while True:
        result = random.randint(0, 100000000)
        if is_prime(result):
            return result


def generate_keypair():
    p = generate_prime_number()
    q = generate_prime_number()

    while p == q:
        q = generate_prime_number()
        q = generate_prime_number()

    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randint(2, phi - 1)
    g = gcd(e, phi)

    while g != 1:
        e = random.randint(2, phi - 1)
        g = gcd(e, phi)

    d = extendedgcd(e, phi)[1]

    privateFile = open("key/privateKey.pri", "w")
    publicFile = open("key/publicKey.pub", "w")

    privateFile.write(str(d) + " " + str(n))
    publicFile.write(str(e) + " " + str(n))

    privateFile.close()
    publicFile.close()
    messagebox.showinfo(title="Finish", message="Key generated successfully! Check the key folder!")
    return ((e, n), (d, n))


def encrypt_rsa(plaintext, private_key):
    d, n = private_key
    blocksize = math.ceil(n.bit_length() / 8)
    plainblocks = [bytes.fromhex('00') + plaintext[i:i+blocksize-1] for i in range(0, len(plaintext), blocksize-1)]

    pad_length = blocksize - len(plainblocks[-1])
    if pad_length:
        plainblocks[-1] = bytes.fromhex('00') * pad_length + plainblocks[-1]

    plainblocks = [int.from_bytes(block, byteorder='big') for block in plainblocks]
    cipherblocks = [pow(block, d, n) for block in plainblocks]
    cipherblocks = [block.to_bytes(blocksize, byteorder='big', signed=False) for block in cipherblocks]
    chipertext = b"".join(cipherblocks)
    chipertext += pad_length.to_bytes(4, byteorder='big', signed=False)
    return chipertext.hex()


def decrypt_rsa(ciphertext, public_key):
    e, n = public_key
    blocksize = (n.bit_length() + 7) // 8
    cipherblocks, pad = ciphertext[:-4], int.from_bytes(ciphertext[-4:], byteorder='big', signed=False)
    cipherblocks = [int.from_bytes(cipherblocks[i:i + blocksize], byteorder='big', signed=False) for i in range(0, len(cipherblocks), blocksize)]

    plainblocks = [pow(block, e, n).to_bytes(length=blocksize, byteorder='big', signed=False) for block in cipherblocks]
    plainblocks[-1] = plainblocks[-1][pad:]

    plaintext = b"".join(block[1:] for block in plainblocks).hex()

    return plaintext

if __name__ == "__main__":
    print(generate_keypair())

