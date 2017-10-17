#!/usr/bin/env python3
# -*- coding: utf-8 -*-

P = 10267
Q = 40163
E = 69439


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
