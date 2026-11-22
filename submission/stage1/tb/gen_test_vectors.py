#!/usr/bin/env python3
"""Generate 1000 random AES-128 test vectors for the hardware testbench.
Uses the `cryptography` library as the golden reference.
Output format: one line per vector — hex plaintext, hex key, hex ciphertext
"""

import os
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

NUM_VECTORS = 1000

def aes128_encrypt(plaintext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()

def main():
    outfile = sys.argv[1] if len(sys.argv) > 1 else "test_vectors.hex"
    with open(outfile, "w") as f:
        for _ in range(NUM_VECTORS):
            pt  = os.urandom(16)
            key = os.urandom(16)
            ct  = aes128_encrypt(pt, key)
            f.write(f"{pt.hex()} {key.hex()} {ct.hex()}\n")
    print(f"Generated {NUM_VECTORS} random AES-128 test vectors -> {outfile}")

if __name__ == "__main__":
    main()
