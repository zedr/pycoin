#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64

# Cannot pick primes greater than 1000
P = 389
Q = 673
E = 31139


def is_prime(num: int) -> bool:
    return num > 1 and all(num % i for i in range(2, num))


def egcd(a: int, b: int) -> tuple:
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a: int, m: int) -> int:
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


def _enc(num: int, key: tuple) -> int:
    modulus, a = key
    return pow(num, a, modulus) # (num ** a) % modulus


def _enc_str(text: str, key: tuple) -> bytes:
    return "".join(chr(_enc(ord(ch), key)) for ch in text)


def encrypt(plaintext: str, key: tuple) -> str:
    return base64.b64encode(_enc_str(plaintext, key).encode())


def decrypt(cyphertext: bytes, key: tuple) -> str:
    return _enc_str(base64.b64decode(cyphertext).decode(), key)


assert is_prime(P)
assert is_prime(Q)
assert is_prime(E)

MODULUS = P * Q
T = (P - 1) * (Q - 1)
# UNSAFE: skip the check for coprimes
PRIVATE_KEY = (MODULUS, modinv(E, T))
PUBLIC_KEY = (MODULUS, E)
PUBLIC_KEY_NAME = "{}-{}".format(*PUBLIC_KEY)

if __name__ == "__main__":
    plaintext = "dublin"
    cyphertext = encrypt(plaintext, PRIVATE_KEY)
    print(cyphertext)
    plaintext2 = decrypt(cyphertext, PUBLIC_KEY)
    print(plaintext2)
