#!/usr/bin/env python3
import asyncio


def main():
    while True:
        cmd, *args = input("? ").split(" ")
        if cmd.lower() == "say":
            print(" ".join(args))
        else:
            print("Unknown command: {}".format(cmd))

if __name__ == "__main__":
    main()
