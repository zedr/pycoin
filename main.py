#!/usr/bin/env python3
import asyncio
import socket

BIND_ADDR = "127.1"
BROADCAST_ADDR = "0.0.0.0"
PORT = 1337


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
        print("Connected!")


def main():
    loop = asyncio.get_event_loop()
    protocol = loop.create_datagram_endpoint(
        _ChatProtocol,
        local_addr=(BIND_ADDR, PORT)
    )
    loop.run_until_complete(protocol)
    while True:
        cmd, *args = input("? ").split(" ")
        if cmd.lower() == "say":
            message = " ".join(args)
            print(message)
        else:
            print("Unknown command: {}".format(cmd))

if __name__ == "__main__":
    main()
