#!/usr/bin/env python3
# -*- coding: utf-8 -*-

P = 10267
Q = 40163
E = 69439


def is_prime(num: int) -> bool:
    return num > 1 and all(num % i for i in range(2, num))


def _eea(a: int, b: int) -> tuple:
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = _eea(b % a, a)
        return (g, y - (b // a) * x, x)

def eea(a: int, b: int) -> int:
    return _eea(a, b)[0]
