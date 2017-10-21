#!/usr/bin/env python
# -*- coding: utf-8 -*-

from encrypt import is_prime


def main():
    for n in range(1000):
        if is_prime(n):
            print(n)


if __name__ == "__main__":
    main()
