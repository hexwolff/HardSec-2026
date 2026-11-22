#!/usr/bin/env python3
"""
cpa_live_demo.py — Live Interactive Demonstration of Correlation Power Analysis (CPA)
HardSec 2026

Demonstrates step-by-step how last-round CPA breaks iterative hardware AES-128
by correlating Hamming Distance transitions against power measurements.
"""

import os
import sys
import time
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))
from generate_traces import (
    INV_SBOX, SR_PERM, recover_master_key, key_expand
)

TRACE_DIR = os.path.join(os.path.dirname(__file__), "traces")

def main():
    print("\033[1;36m" + "="*70 + "\033[0m")
    print("\033[1;33m       HARDSEC 2026: LIVE CORRELATION POWER ANALYSIS (CPA) DEMO\033[0m")
    print("\033[1;36m" + "="*70 + "\033[0m")
    print("Target Architecture : Iterative 11-Cycle AES-128 Hardware Core (SystemVerilog)")
    print("Leakage Model       : CMOS Register Hamming Distance (HD) on Round 9 -> 10")
    print("Methodology Source  : ChipWhisperer SCA201 (Hardware AES CPA)")
    print("\033[1;36m" + "-"*70 + "\033[0m")

    # 1. Load Traces
    print("\n[+] Loading pre-acquired power traces from simulated RTL datapath...")
    ct = np.load(os.path.join(TRACE_DIR, "cpa_ciphertexts.npy"))
    tr = np.load(os.path.join(TRACE_DIR, "cpa_traces.npy"))
    secret_key = np.load(os.path.join(TRACE_DIR, "secret_key.npy"))
    N = 1000  # use 1000 traces for demo

    print(f"    Loaded {N} power traces. Each trace has 11 time samples (Cycles 0 to 10).")
    print(f"    Target Secret Key : \033[1;32m{bytes(secret_key).hex()}\033[0m (Hidden from attacker!)")

    # Derive true Round Key 10 for display/comparison
    rk = list(secret_key)
    for r in range(1, 11):
        rk = key_expand(rk, r)
    true_rk10 = np.array(rk, dtype=np.uint8)
    print(f"    True Round Key 10 : \033[1;32m{bytes(true_rk10).hex()}\033[0m (Target of CPA attack)\n")

    input(">>> Press [ENTER] to launch the Last-Round CPA Attack...")

    print("\n" + "="*70)
    print(" ATTACK IN PROGRESS: Testing 256 Key Guesses per Byte at Cycle 10")
    print("="*70)
    print(f"{'Byte':<5} | {'True':<4} | {'Best Guess':<10} | {'|Correlation|':<13} | {'2nd Best':<8} | {'Margin':<8} | {'Status'}")
    print("-" * 70)

    inv_sbox_arr = np.array(INV_SBOX, dtype=np.uint8)
    hw_lut = np.array([bin(i).count('1') for i in range(256)], dtype=np.float64)

    # Pre-center trace slice at t=10
    tr_slice = tr[:N, 10]
    tr_centered = tr_slice - tr_slice.mean()
    tr_ss = np.sqrt((tr_centered ** 2).sum())

    recovered_rk10 = []

    for byte_idx in range(16):
        ct_byte = ct[:N, byte_idx]
        ct_reg  = ct[:N, SR_PERM[byte_idx]]

        corrs = np.zeros(256)
        for kg in range(256):
            # Model: S9 = InvSBox(CT[i] ^ kg)
            s9 = inv_sbox_arr[ct_byte ^ kg]
            # Hypothetical HD = HW(S9 ^ CT_reg)
            hyp = hw_lut[s9 ^ ct_reg]
            hyp_c = hyp - hyp.mean()
            hyp_s = np.sqrt((hyp_c ** 2).sum())
            if hyp_s > 1e-12:
                corrs[kg] = abs(np.dot(tr_centered, hyp_c) / (tr_ss * hyp_s))

        # Rank guesses
        sorted_guesses = np.argsort(-corrs)
        best_g = sorted_guesses[0]
        second_g = sorted_guesses[1]
        best_r = corrs[best_g]
        second_r = corrs[second_g]
        margin = best_r - second_r
        recovered_rk10.append(best_g)

        is_match = (best_g == true_rk10[byte_idx])
        status = "\033[1;32m[LOCKED]\033[0m" if is_match else "\033[1;31m[FAIL]\033[0m"

        # Print line with small delay for visual dramatic effect
        print(f" {byte_idx:2d}   | 0x{true_rk10[byte_idx]:02x} | 0x{best_g:02x}       | {best_r:10.4f}  | 0x{second_g:02x}   | {margin:7.4f} | {status}")
        time.sleep(0.08)

    print("-" * 70)
    rec_rk10_bytes = bytes(recovered_rk10)
    print(f"\n[+] Full Round Key 10 Recovered: \033[1;32m{rec_rk10_bytes.hex()}\033[0m")
    if rec_rk10_bytes == bytes(true_rk10):
        print("    \033[1;32m>>> 16 / 16 ROUND KEY BYTES CORRECTLY RECOVERED! <<<\033[0m")

    print("\n[+] Inverting AES-128 Key Schedule (Rounds 10 -> 0)...")
    time.sleep(0.3)
    rec_master = bytes(recover_master_key(list(rec_rk10_bytes)))
    print(f"    Master Key Recovered : \033[1;32m{rec_master.hex()}\033[0m")
    print(f"    Target Secret Key    : \033[1;32m{bytes(secret_key).hex()}\033[0m")

    if rec_master == bytes(secret_key):
        print("\n\033[1;32m" + "*"*70)
        print("       SUCCESS! 128-BIT AES MASTER KEY FULLY EXTRACTED VIA CPA!")
        print("*"*70 + "\033[0m\n")

if __name__ == "__main__":
    main()
