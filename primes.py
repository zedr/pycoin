#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def is_prime(num: int) -> bool:
    return num > 1 and all(num % i for i in range(2, num))

