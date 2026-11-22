#!/usr/bin/env python3
"""
generate_masked_traces.py — Side-Channel Trace Generation for Masked AES-128
HardSec 2026 — Stage 2C

Generates simulated power traces for the First-Order Boolean Masked AES-128 core.
In the masked core, all state register transitions operate on masked values:
  state_reg[t] = real_state[t] ⊕ mask[t]
Power model:
  P(t) = HW(state_reg[t] ⊕ state_reg[t-1]) + N(0, σ²)

Outputs (saved to sca/traces_masked/):
  - cpa_plaintexts.npy   : (N, 16) uint8
  - cpa_ciphertexts.npy  : (N, 16) uint8
  - cpa_traces.npy       : (N, 11) float64
  - tvla_fixed_traces.npy: (N, 11) float64
  - tvla_rand_traces.npy : (N, 11) float64
  - secret_key.npy       : (16,) uint8
"""

import argparse
import os
import sys
import numpy as np

# Import AES functions from generate_traces
sys.path.insert(0, os.path.dirname(__file__))
from generate_traces import (
    SBOX, RCON, SR_PERM, xtime, mix_column, sub_bytes,
    shift_rows, mix_columns, add_round_key, key_expand,
    hamming_weight
)

def aes128_masked_encrypt_with_states(pt: list[int], key: list[int], rng: np.random.Generator) -> tuple:
    """
    Simulates the First-Order Boolean Masked AES-128 core cycle-by-cycle.
    Tracks both real intermediate states and the masked register states.
    """
    masked_states = []
    rk = list(key)

    # Initial mask M0 (16 random bytes from PRNG)
    m0 = list(rng.integers(0, 256, size=16, dtype=np.uint8))
    cur_mask = list(m0)

    # Cycle 0: Initial AddRoundKey (masked)
    real_state = add_round_key(pt, rk)
    masked_state = [s ^ m for s, m in zip(real_state, cur_mask)]
    masked_states.append(list(masked_state))

    # Rounds 1 to 9
    for r in range(1, 10):
        rk = key_expand(rk, r)
        # Fresh mask for S-box output (from PRNG)
        m_out = list(rng.integers(0, 256, size=16, dtype=np.uint8))
        
        # Real state computation
        real_state = sub_bytes(real_state)
        real_state = shift_rows(real_state)
        real_state = mix_columns(real_state)
        real_state = add_round_key(real_state, rk)

        # Mask propagation through linear layers:
        # ShiftRows on m_out
        m_sr = shift_rows(m_out)
        # MixColumns on m_sr
        m_mc = mix_columns(m_sr)
        cur_mask = m_mc

        # The physical register holds real_state ^ cur_mask
        masked_state = [s ^ m for s, m in zip(real_state, cur_mask)]
        masked_states.append(list(masked_state))

    # Round 10: Final round (no MixColumns)
    rk = key_expand(rk, 10)
    m_out = list(rng.integers(0, 256, size=16, dtype=np.uint8))
    
    real_state = sub_bytes(real_state)
    real_state = shift_rows(real_state)
    real_state = add_round_key(real_state, rk)

    m_sr = shift_rows(m_out)
    cur_mask = m_sr

    masked_state = [s ^ m for s, m in zip(real_state, cur_mask)]
    masked_states.append(list(masked_state))

    # Final unmasked ciphertext
    ct = list(real_state)

    return masked_states, ct

def hamming_distance_trace(masked_states: list[list[int]]) -> np.ndarray:
    """Compute Hamming Distance switching power between masked state registers."""
    trace = np.zeros(11, dtype=np.float64)
    trace[0] = sum(hamming_weight(b) for b in masked_states[0])
    for t in range(1, 11):
        hd = sum(hamming_weight(masked_states[t][j] ^ masked_states[t-1][j]) for j in range(16))
        trace[t] = hd
    return trace

def generate_masked_dataset(n: int, key_bytes: list[int], sigma: float,
                            fixed_pt: list[int] | None = None, seed: int = 42):
    rng = np.random.default_rng(seed)
    plaintexts = np.zeros((n, 16), dtype=np.uint8)
    ciphertexts = np.zeros((n, 16), dtype=np.uint8)
    traces = np.zeros((n, 11), dtype=np.float64)

    for i in range(n):
        if fixed_pt is not None:
            pt = list(fixed_pt)
        else:
            pt = list(rng.integers(0, 256, size=16, dtype=np.uint8))

        m_states, ct = aes128_masked_encrypt_with_states(pt, key_bytes, rng)
        hd_trace = hamming_distance_trace(m_states)

        noise = rng.normal(0, sigma, size=11)
        traces[i] = hd_trace + noise

        plaintexts[i] = pt
        ciphertexts[i] = ct

    return plaintexts, ciphertexts, traces

def main():
    parser = argparse.ArgumentParser(description="Masked AES-128 SCA Trace Generator")
    parser.add_argument("--n-cpa", type=int, default=5000,
                        help="Number of CPA traces (default: 5000 for rigorous proof)")
    parser.add_argument("--n-tvla", type=int, default=5000,
                        help="Number of TVLA traces per group (default: 5000)")
    parser.add_argument("--sigma", type=float, default=1.0,
                        help="Gaussian noise σ (default: 1.0)")
    parser.add_argument("--outdir", type=str, default="sca/traces_masked",
                        help="Output directory (default: sca/traces_masked)")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    # Secret key (same as unpatched for direct comparison)
    secret_key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

    print(f"Secret Key: {bytes(secret_key).hex()}")
    print(f"Generating {args.n_cpa} Masked CPA traces...")
    cpa_pt, cpa_ct, cpa_traces = generate_masked_dataset(
        args.n_cpa, secret_key, args.sigma, seed=42
    )

    # Verify that ciphertext matches standard AES (from cryptography library)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(bytes(secret_key)), modes.ECB())
    enc = cipher.encryptor()
    ref_ct = enc.update(bytes(cpa_pt[0])) + enc.finalize()
    assert list(ref_ct) == list(cpa_ct[0]), "Masked AES functional output mismatch!"
    print("  ✓ Masked AES ciphertext output matches NIST AES reference")

    np.save(os.path.join(args.outdir, "cpa_plaintexts.npy"), cpa_pt)
    np.save(os.path.join(args.outdir, "cpa_ciphertexts.npy"), cpa_ct)
    np.save(os.path.join(args.outdir, "cpa_traces.npy"), cpa_traces)
    print("  ✓ Saved CPA dataset")

    # TVLA datasets
    fixed_pt = [0x00] * 16
    print(f"\nGenerating {args.n_tvla} TVLA fixed-PT traces...")
    _, _, tvla_fixed = generate_masked_dataset(
        args.n_tvla, secret_key, args.sigma, fixed_pt=fixed_pt, seed=100
    )

    print(f"Generating {args.n_tvla} TVLA random-PT traces...")
    _, _, tvla_rand = generate_masked_dataset(
        args.n_tvla, secret_key, args.sigma, seed=200
    )

    np.save(os.path.join(args.outdir, "tvla_fixed_traces.npy"), tvla_fixed)
    np.save(os.path.join(args.outdir, "tvla_rand_traces.npy"), tvla_rand)
    np.save(os.path.join(args.outdir, "secret_key.npy"), np.array(secret_key, dtype=np.uint8))
    print("  ✓ Saved TVLA dataset")
    print(f"\nMasked trace generation complete! Saved to {args.outdir}/")

if __name__ == "__main__":
    main()
