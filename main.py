#!/usr/bin/env python3
import asyncio
import socket
import base64

BIND_ADDR = "0"
BROADCAST_ADDR = "0"
PORT = 1337

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


class _ChatProtocol(asyncio.Protocol):
    """A protocol for chatting among peers.
    """
    transport = None

    @classmethod
    def connection_made(cls, transport):
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        cls.transport = transport

    def datagram_received(self, data, addr):
        ip, port = addr
        message = data.decode()
        print("\n{} said {}".format(ip, message))


def say(message):
    _ChatProtocol.transport.sendto(message.encode(), (BROADCAST_ADDR, PORT))


async def main():
    while True:
        line = await loop.run_in_executor(None, input, "? ")
        cmd, *args = line.split(" ")
        if cmd.lower() == "say":
            message = " ".join(args)
            print("Say: " + message)
            say(message)
        else:
            print("Unknown command: {}".format(cmd))


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    protocol = loop.create_datagram_endpoint(
        _ChatProtocol,
        local_addr=(BIND_ADDR, PORT)
    )
    tasks = (protocol, main())
    loop.run_until_complete(asyncio.gather(*tasks))
