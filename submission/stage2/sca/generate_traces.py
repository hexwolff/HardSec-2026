#!/usr/bin/env python3
"""
generate_traces.py — AES-128 Side-Channel Trace Generation
HardSec 2026

Generates simulated power traces using a cycle-accurate Python AES-128 model
that mirrors the hardware exactly (same state_reg / key_reg transitions).

Power model: P(t) = HW(state[t] ⊕ state[t-1]) + N(0, σ²)  (Hamming Distance)

Outputs (saved to sca/traces/):
  - cpa_plaintexts.npy   : (N, 16) uint8
  - cpa_ciphertexts.npy  : (N, 16) uint8
  - cpa_traces.npy       : (N, 11) float64 — HD power trace per encryption
  - tvla_fixed_traces.npy: (N, 11) float64 — fixed-plaintext set
  - tvla_rand_traces.npy : (N, 11) float64 — random-plaintext set
  - secret_key.npy       : (16,) uint8

Usage:
  python3 sca/generate_traces.py [--n-cpa 2000] [--n-tvla 2000] [--sigma 1.0]
"""

import argparse
import os
import sys
import numpy as np

# ══════════════════════════════════════════════════════════════════════════════
# AES-128 reference implementation with full intermediate state logging
# Mirrors the hardware datapath exactly:
#   Cycle 0:  state = PT ⊕ Key0
#   Cycle 1–9: SubBytes → ShiftRows → MixColumns → AddRoundKey
#   Cycle 10:  SubBytes → ShiftRows → AddRoundKey (no MixColumns)
# ══════════════════════════════════════════════════════════════════════════════

# Forward S-Box (FIPS 197 Figure 7)
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# Inverse S-Box
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

# Round constants
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# ShiftRows permutation (byte index mapping)
# Input byte j → output byte SR_PERM[j]
# Row 0: no shift, Row 1: left 1, Row 2: left 2, Row 3: left 3
SR_PERM = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]

# Inverse ShiftRows permutation
INV_SR_PERM = [0] * 16
for _i, _v in enumerate(SR_PERM):
    INV_SR_PERM[_v] = _i


def xtime(a: int) -> int:
    """Multiply by {02} in GF(2^8)."""
    return ((a << 1) ^ (0x1b if a & 0x80 else 0)) & 0xff


def mix_column(col: list[int]) -> list[int]:
    """MixColumns on a single 4-byte column."""
    a0, a1, a2, a3 = col
    return [
        xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3,
        a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3,
        a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3,
        xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3),
    ]


def sub_bytes(state: list[int]) -> list[int]:
    return [SBOX[b] for b in state]


def shift_rows(state: list[int]) -> list[int]:
    out = [0] * 16
    for i in range(16):
        out[i] = state[SR_PERM[i]]
    return out


def mix_columns(state: list[int]) -> list[int]:
    out = list(state)
    for c in range(4):
        col = state[4*c : 4*c+4]
        mixed = mix_column(col)
        out[4*c : 4*c+4] = mixed
    return out


def add_round_key(state: list[int], rk: list[int]) -> list[int]:
    return [s ^ k for s, k in zip(state, rk)]


def key_expand(key: list[int], rnd: int) -> list[int]:
    """Compute next round key from current (matches aes_key_expand.sv)."""
    w = [key[4*i : 4*i+4] for i in range(4)]
    # RotWord + SubWord on w[3]
    rot = [w[3][1], w[3][2], w[3][3], w[3][0]]
    sub = [SBOX[b] for b in rot]
    # XOR with Rcon
    sub[0] ^= RCON[rnd]
    # Derive new words
    nw = [None] * 4
    nw[0] = [w[0][j] ^ sub[j] for j in range(4)]
    nw[1] = [w[1][j] ^ nw[0][j] for j in range(4)]
    nw[2] = [w[2][j] ^ nw[1][j] for j in range(4)]
    nw[3] = [w[3][j] ^ nw[2][j] for j in range(4)]
    return nw[0] + nw[1] + nw[2] + nw[3]


def aes128_encrypt_with_states(pt: list[int], key: list[int]) -> tuple:
    """
    AES-128 encryption returning all intermediate state_reg values.

    Returns:
        states: list of 11 state snapshots (each 16 bytes)
                states[0] = PT ⊕ Key0  (cycle 0 result)
                states[1..9] = round 1..9 outputs
                states[10] = ciphertext (round 10 output)
        ct: ciphertext (same as states[10])
    """
    states = []
    rk = list(key)

    # Cycle 0: Initial AddRoundKey
    state = add_round_key(pt, rk)
    states.append(list(state))

    # Cycles 1–9: full rounds
    for r in range(1, 10):
        rk = key_expand(rk, r)
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, rk)
        states.append(list(state))

    # Cycle 10: final round (no MixColumns)
    rk = key_expand(rk, 10)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, rk)
    states.append(list(state))

    return states, state


def hamming_weight(x: int) -> int:
    return bin(x).count('1')


def hamming_distance_trace(states: list[list[int]]) -> np.ndarray:
    """
    Compute the Hamming Distance power trace from state snapshots.

    HD[t] = HW(state[t] ⊕ state[t-1]) for t=1..10
    HD[0] = HW(state[0] ⊕ 0) = HW(state[0])  (register was zeroed by reset)

    Returns: (11,) float64 array
    """
    trace = np.zeros(11, dtype=np.float64)

    # Cycle 0: transition from zero (reset state) to initial AddRoundKey
    trace[0] = sum(hamming_weight(b) for b in states[0])

    # Cycles 1–10: transition between consecutive states
    for t in range(1, 11):
        hd = sum(hamming_weight(states[t][j] ^ states[t-1][j]) for j in range(16))
        trace[t] = hd

    return trace


# ══════════════════════════════════════════════════════════════════════════════
# Key schedule inversion (to recover master key from round key 10)
# ══════════════════════════════════════════════════════════════════════════════

def inv_key_expand(key: list[int], rnd: int) -> list[int]:
    """Invert one key expansion step: given round key `rnd`, recover round key `rnd-1`."""
    w = [key[4*i : 4*i+4] for i in range(4)]
    # Reverse the derivation chain
    pw = [None] * 4
    pw[3] = [w[3][j] ^ w[2][j] for j in range(4)]
    pw[2] = [w[2][j] ^ w[1][j] for j in range(4)]
    pw[1] = [w[1][j] ^ w[0][j] for j in range(4)]
    # pw[0] = w[0] ^ SubWord(RotWord(pw[3])) ^ Rcon
    rot = [pw[3][1], pw[3][2], pw[3][3], pw[3][0]]
    sub = [SBOX[b] for b in rot]
    sub[0] ^= RCON[rnd]
    pw[0] = [w[0][j] ^ sub[j] for j in range(4)]
    return pw[0] + pw[1] + pw[2] + pw[3]


def recover_master_key(round_key_10: list[int]) -> list[int]:
    """Invert the AES-128 key schedule from round 10 back to master key."""
    rk = list(round_key_10)
    for r in range(10, 0, -1):
        rk = inv_key_expand(rk, r)
    return rk


# ══════════════════════════════════════════════════════════════════════════════
# Trace generation
# ══════════════════════════════════════════════════════════════════════════════

def generate_traces(n: int, key_bytes: list[int], sigma: float,
                    fixed_pt: list[int] | None = None, seed: int = 42):
    """
    Generate n AES-128 power traces.

    Args:
        n: number of encryptions
        key_bytes: 16-byte key
        sigma: Gaussian noise standard deviation
        fixed_pt: if provided, use this fixed plaintext (for TVLA fixed set)
        seed: RNG seed for reproducibility

    Returns:
        plaintexts:  (n, 16) uint8
        ciphertexts: (n, 16) uint8
        traces:      (n, 11) float64
    """
    rng = np.random.default_rng(seed)
    plaintexts = np.zeros((n, 16), dtype=np.uint8)
    ciphertexts = np.zeros((n, 16), dtype=np.uint8)
    traces = np.zeros((n, 11), dtype=np.float64)

    for i in range(n):
        if fixed_pt is not None:
            pt = list(fixed_pt)
        else:
            pt = list(rng.integers(0, 256, size=16, dtype=np.uint8))

        states, ct = aes128_encrypt_with_states(pt, key_bytes)
        hd_trace = hamming_distance_trace(states)

        # Add Gaussian noise
        noise = rng.normal(0, sigma, size=11)
        traces[i] = hd_trace + noise

        plaintexts[i] = pt
        ciphertexts[i] = ct

    return plaintexts, ciphertexts, traces


def main():
    parser = argparse.ArgumentParser(description="AES-128 SCA Trace Generator")
    parser.add_argument("--n-cpa", type=int, default=2000,
                        help="Number of CPA traces (default: 2000)")
    parser.add_argument("--n-tvla", type=int, default=2000,
                        help="Number of TVLA traces per group (default: 2000)")
    parser.add_argument("--sigma", type=float, default=1.0,
                        help="Gaussian noise σ (default: 1.0)")
    parser.add_argument("--outdir", type=str, default="sca/traces",
                        help="Output directory (default: sca/traces)")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    # Secret key (NIST FIPS 197 Appendix B)
    secret_key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

    print(f"Secret Key: {bytes(secret_key).hex()}")
    print(f"Noise σ = {args.sigma}")

    # ── CPA traces ──────────────────────────────────────────────────────
    print(f"\nGenerating {args.n_cpa} CPA traces (random PT, fixed key)...")
    cpa_pt, cpa_ct, cpa_traces = generate_traces(
        args.n_cpa, secret_key, args.sigma, seed=42
    )

    # Verify first trace against cryptography library
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(bytes(secret_key)), modes.ECB())
    enc = cipher.encryptor()
    ref_ct = enc.update(bytes(cpa_pt[0])) + enc.finalize()
    assert list(ref_ct) == list(cpa_ct[0]), "Python AES mismatch with cryptography library!"
    print("  ✓ Python AES verified against cryptography library")

    np.save(os.path.join(args.outdir, "cpa_plaintexts.npy"), cpa_pt)
    np.save(os.path.join(args.outdir, "cpa_ciphertexts.npy"), cpa_ct)
    np.save(os.path.join(args.outdir, "cpa_traces.npy"), cpa_traces)
    print(f"  ✓ Saved: cpa_plaintexts.npy, cpa_ciphertexts.npy, cpa_traces.npy")
    print(f"    Trace shape: {cpa_traces.shape}, dtype: {cpa_traces.dtype}")

    # ── TVLA traces ─────────────────────────────────────────────────────
    fixed_pt = [0x00] * 16  # fixed plaintext for TVLA group A

    print(f"\nGenerating {args.n_tvla} TVLA fixed-PT traces...")
    _, _, tvla_fixed = generate_traces(
        args.n_tvla, secret_key, args.sigma, fixed_pt=fixed_pt, seed=100
    )

    print(f"Generating {args.n_tvla} TVLA random-PT traces...")
    _, _, tvla_rand = generate_traces(
        args.n_tvla, secret_key, args.sigma, seed=200
    )

    np.save(os.path.join(args.outdir, "tvla_fixed_traces.npy"), tvla_fixed)
    np.save(os.path.join(args.outdir, "tvla_rand_traces.npy"), tvla_rand)
    print(f"  ✓ Saved: tvla_fixed_traces.npy, tvla_rand_traces.npy")

    # Save key
    np.save(os.path.join(args.outdir, "secret_key.npy"), np.array(secret_key, dtype=np.uint8))

    # ── Summary ─────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"Trace generation complete!")
    print(f"  CPA:  {args.n_cpa} traces × 11 time samples")
    print(f"  TVLA: {args.n_tvla} fixed + {args.n_tvla} random traces")
    print(f"  σ = {args.sigma}")
    print(f"  Output: {args.outdir}/")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
