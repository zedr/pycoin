import sys

import hashlib


def is_valid_hash(hsh: str, dif: int) -> bool:
    return hsh[:dif] == '0' * dif


def find_hash(plaintext: str, dif: int) -> str:
    hash_ = ""
    nonce = 1
    while (not is_valid_hash(hash_, dif)):
        hash_ = hashlib.md5((plaintext + str(nonce)).encode()).hexdigest()
        nonce += 1
    return "{}:{}".format(hash_, nonce)


def main():
    dif = int(sys.argv[1])
    plaintext = sys.argv[2]
    print(find_hash(plaintext, dif))

if __name__ == "__main__":
    if len(sys.argv) == 3:
        main()
