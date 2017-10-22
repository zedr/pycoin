#!/usr/bin/env python3
import asyncio
import socket
import base64
import logging
import datetime as dt
from hashlib import sha256
from collections import namedtuple

logging.basicConfig(level=logging.INFO)

NAME = "Rigel"
BIND_ADDR = "0"
BROADCAST_ADDR = "0"
PORT = 31139

# Cannot pick primes greater than 1000
P = 389
Q = 673
E = PORT


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


def _enc_str(text: str, key: tuple) -> str:
    return "".join(chr(_enc(ord(ch), key)) for ch in text)


def encrypt(plaintext: str, key: tuple) -> bytes:
    return base64.b64encode(_enc_str(plaintext, key).encode())


def decrypt(cyphertext: bytes, key: tuple) -> str:
    return _enc_str(base64.b64decode(cyphertext).decode(), key)


def sign(plaintext: str, key: tuple) -> bytes:
    hsh = sha256(plaintext.encode()).hexdigest()[:8]
    return encrypt(hsh, key)


def verify(plaintext: str, key: tuple, signature: bytes) -> bool:
    hsh = sha256(plaintext.encode()).hexdigest()[:8]
    return hsh == decrypt(signature, key)


assert is_prime(P)
assert is_prime(Q)
assert is_prime(E)


MODULUS = P * Q
T = (P - 1) * (Q - 1)
# UNSAFE: skip the check for coprimes
PRIVATE_KEY = (MODULUS, modinv(E, T))
PUBLIC_KEY = (MODULUS, E)

################################################################################
# Blockchain

class Transaction:
    def __init__(self, prev_hash: str, pub_key: int, signature: bytes):
        self._prev_hash = prev_hash or "0"
        self._pub_key = pub_key
        self._signature = signature or b"0"

    def __str__(self):
        return "{} {} {}".format(
            self._signature.decode(), self._pub_key, self._prev_hash
        )

    def as_hash(self) -> str:
        return sha256(str(self).encode()).hexdigest()[:8]

    def transfer_to(self, pub_key: int) -> 'Transaction':
        hsh = self.as_hash()
        payload = "{} {}".format(hsh, pub_key)
        signature = sign(payload, PRIVATE_KEY)
        return Transaction(hsh, pub_key, signature)

    def verify_for(self, pub_key: int) -> bool:
        payload = "{} {}".format(self._prev_hash, self._pub_key)
        if self.is_coinbase:
            return True
        else:
            return verify(
                payload, 
                (pub_key, E),
                self._signature
            )

    @property
    def is_coinbase(self):
        return self._prev_hash == self._signature.decode() == "0"


class Block:
    def __init__(self, prev: 'Block' = None):
        self._transactions = []
        self._prev = prev

    @property
    def prev(self):
        return self._prev

    def add(self, *txs) -> int:
        self._transactions += txs
        return len(self._transactions)

    def as_hash(self) -> str:
        payload = self._prev.as_hash() if self._prev else ""
        payload = " ".join(tx.as_hash() for tx in self._transactions).encode()
        return sha256(payload).hexdigest()[:8]

    @property
    def is_genesis(self):
        return not self._prev

    def __eq__(self, other):
        return self.as_hash() == other.as_hash()


class BlockChain:
    def __init__(self):
        self.tip = gb = Block()
        gb.add(
            Transaction("", 261797, b""),
            Transaction("", 261797, b""),
            Transaction("", 261797, b""),
            Transaction("", 261797, b""),
            Transaction("", 261797, b"")
        )

    def add(self, block: Block) -> bool:
        if self.tip == block.prev:
            self.tip = block
            return True
        else:
            return False


################################################################################
# Network

class _CoinProtocol(asyncio.Protocol):
    """A protocol for chatting among peers.
    """
    transport = None
    # Our blockchain
    _bc = BlockChain()
    # The current block being assembled
    _cb = None

    @classmethod
    def connection_made(cls, transport):
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        cls.transport = transport

    def datagram_received(self, data, addr):
        ip, port = addr
        payload = data.decode()
        name, key, cmd, *args = payload.split(" ")
        message = " ".join(args)
        logging.info(
            "Received '{}' from {} {} {}: {}".format(
                cmd, name, ip, key, message
            )
        )
        if cmd == "tx":
            sig, num, hsh = args
            key = int(num)
            tr = Transaction(hsh, key, sig.encode())
            if key == MODULUS:
                logging.info("Received a Pycoin! " + tr.as_hash())
            else:
                logging.info("Got TX {} for {}".format(tr.as_hash(), key))



def broadcast(message):
    payload = "{} {} {}".format(NAME, MODULUS, message)
    _CoinProtocol.transport.sendto(payload.encode(), (BROADCAST_ADDR, PORT))


def transfer(to: int):
    transaction = Transaction("", to, b"")
    broadcast("tx {}".format(transaction))


async def main():
    while True:
        line = await loop.run_in_executor(None, input, "? ")
        cmd, *args = line.split(" ")
        if cmd:
            if cmd == "say":
                broadcast(" ".join((["say"] + args)))
            elif cmd == "tx":
                to = args[0]
                transfer(to)
            else:
                logging.error("Unknown command: %s", cmd)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    protocol = loop.create_datagram_endpoint(
        _CoinProtocol,
        local_addr=(BIND_ADDR, PORT)
    )
    tasks = (protocol, main())
    loop.run_until_complete(asyncio.gather(*tasks))
