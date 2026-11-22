#!/usr/bin/env python3
"""
cpa_attack_and_tvla.py — Correlation Power Analysis + TVLA on AES-128
HardSec 2026 — Stage 2A

Attacks the unpatched AES-128 core using the Hamming Distance (HD)
leakage model on the Round 9 → Round 10 state register transition.

Attack strategy (FIPS 197, last-round CPA):
  For each of the 16 key bytes of Round Key 10 (k_{10,i}):
    - Hypothetical Round 9 state byte: s9 = InvSBox(CT[i] ⊕ k)
    - Corresponding ciphertext byte at the SAME register position:
      s10 = CT[InvSR[i]]  (accounting for ShiftRows permutation)
    - Hypothetical HD: H = HW(s9 ⊕ s10)
    - Correlate H across all N traces with the actual power at cycle 10
    - The correct key byte maximises |Pearson correlation|

After recovering all 16 bytes of Round Key 10, invert the key schedule
to obtain the 128-bit master key.

Usage:
  python3 sca/generate_traces.py          # generate traces first
  python3 sca/cpa_attack_and_tvla.py      # run attack + TVLA

Outputs (saved to results/plots/):
  - cpa_correlation_vs_time.png
  - cpa_correlation_vs_traces.png
  - tvla_t_test.png
"""

import os
import sys
import numpy as np

# ── Check for matplotlib ────────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use('Agg')  # non-interactive backend
    import matplotlib.pyplot as plt
except ImportError:
    print("Run:  pip install matplotlib")
    sys.exit(1)

# ── Import helpers from generate_traces ─────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from generate_traces import (
    SBOX, INV_SBOX, INV_SR_PERM, SR_PERM,
    recover_master_key, hamming_weight
)


TRACE_DIR = os.path.join(os.path.dirname(__file__), "traces")
PLOT_DIR  = os.path.join(os.path.dirname(__file__), "..", "results", "plots")


def load_traces():
    """Load trace datasets."""
    ct  = np.load(os.path.join(TRACE_DIR, "cpa_ciphertexts.npy"))
    tr  = np.load(os.path.join(TRACE_DIR, "cpa_traces.npy"))
    key = np.load(os.path.join(TRACE_DIR, "secret_key.npy"))
    return ct, tr, key


def pearson_corr(x: np.ndarray, y: np.ndarray) -> float:
    """Pearson correlation coefficient between 1-D arrays."""
    n = len(x)
    if n < 2:
        return 0.0
    mx, my = x.mean(), y.mean()
    dx, dy = x - mx, y - my
    num = np.dot(dx, dy)
    den = np.sqrt(np.dot(dx, dx) * np.dot(dy, dy))
    return num / den if den > 1e-12 else 0.0


# ══════════════════════════════════════════════════════════════════════════
# CPA Attack
# ══════════════════════════════════════════════════════════════════════════

def cpa_attack(ciphertexts: np.ndarray, traces: np.ndarray,
               max_traces: int | None = None):
    """
    Perform CPA on the last round of AES-128.
    Fully vectorized with numpy for speed.

    Returns:
        recovered_rk10: (16,) uint8 — recovered Round Key 10
        corr_matrix: (16, 256, 11) — correlation for each (byte, guess, time)
    """
    N = traces.shape[0] if max_traces is None else min(max_traces, traces.shape[0])
    ct = ciphertexts[:N]
    tr = traces[:N]
    n_time = tr.shape[1]  # 11 time samples

    # Precompute lookup tables
    inv_sbox_arr = np.array(INV_SBOX, dtype=np.uint8)

    # Precompute HW lookup (0-255 -> hamming weight)
    hw_lut = np.zeros(256, dtype=np.float64)
    for i in range(256):
        hw_lut[i] = bin(i).count('1')

    recovered_rk10 = np.zeros(16, dtype=np.uint8)
    corr_matrix = np.zeros((16, 256, n_time), dtype=np.float64)

    print("\n── CPA Attack (Last-Round HD Model, vectorized) ──")
    print(f"   Traces: {N}, Time samples: {n_time}")

    # Precompute mean-centered traces for Pearson correlation
    tr_mean = tr.mean(axis=0)                    # (11,)
    tr_centered = tr - tr_mean                   # (N, 11)
    tr_ss = np.sqrt((tr_centered ** 2).sum(axis=0))  # (11,)

    for byte_idx in range(16):
        ct_byte = ct[:, byte_idx]                            # (N,)
        ct_reg  = ct[:, SR_PERM[byte_idx]]                    # (N,) state_reg[10] at position SR_PERM[i]

        for kg in range(256):
            # Vectorized hypothetical HD computation
            s9 = inv_sbox_arr[ct_byte ^ kg]                  # (N,) InvSBox(CT[i] ^ k)
            hyp = hw_lut[s9 ^ ct_reg]                        # (N,) HW(s9 ^ s10)

            # Vectorized Pearson correlation across all time samples
            hyp_centered = hyp - hyp.mean()
            hyp_ss = np.sqrt((hyp_centered ** 2).sum())
            if hyp_ss < 1e-12:
                continue
            # (11,) correlations in one dot product
            corr_matrix[byte_idx, kg, :] = (
                tr_centered.T @ hyp_centered  # (11,)
            ) / (tr_ss * hyp_ss + 1e-12)

        # Best guess = max |correlation| at t=10
        recovered_rk10[byte_idx] = np.argmax(np.abs(corr_matrix[byte_idx, :, 10]))

        print(f"   Byte {byte_idx:2d} done — "
              f"guess=0x{recovered_rk10[byte_idx]:02x}, "
              f"|r|={np.abs(corr_matrix[byte_idx, recovered_rk10[byte_idx], 10]):.4f}")

    return recovered_rk10, corr_matrix, []


def compute_convergence(ciphertexts, traces, true_rk10):
    """Compute PGE convergence curves for all 16 bytes (vectorized)."""
    N = traces.shape[0]
    trace_counts = list(range(20, min(N, 1001), 20))
    pge = np.full((16, len(trace_counts)), 255, dtype=np.int32)

    ct = ciphertexts[:N]
    tr = traces[:N]

    inv_sbox_arr = np.array(INV_SBOX, dtype=np.uint8)
    hw_lut = np.zeros(256, dtype=np.float64)
    for i in range(256):
        hw_lut[i] = bin(i).count('1')

    for ti, tc in enumerate(trace_counts):
        tr_slice = tr[:tc, 10]
        tr_c = tr_slice - tr_slice.mean()
        tr_s = np.sqrt((tr_c ** 2).sum())

        for byte_idx in range(16):
            ct_byte = ct[:tc, byte_idx]
            ct_reg  = ct[:tc, SR_PERM[byte_idx]]

            corrs = np.zeros(256)
            for kg in range(256):
                s9 = inv_sbox_arr[ct_byte ^ kg]
                hyp = hw_lut[s9 ^ ct_reg]
                hyp_c = hyp - hyp.mean()
                hyp_s = np.sqrt((hyp_c ** 2).sum())
                if hyp_s < 1e-12:
                    continue
                corrs[kg] = abs(np.dot(tr_c, hyp_c) / (tr_s * hyp_s))

            sorted_idx = np.argsort(-corrs)
            rank = int(np.where(sorted_idx == true_rk10[byte_idx])[0][0])
            pge[byte_idx, ti] = rank

    return trace_counts, pge


# ══════════════════════════════════════════════════════════════════════════
# TVLA (Welch's t-test)
# ══════════════════════════════════════════════════════════════════════════

def welch_ttest(group_a: np.ndarray, group_b: np.ndarray) -> np.ndarray:
    """
    Welch's t-statistic per time sample (column).

    t = (μ_A - μ_B) / sqrt(σ²_A/n_A + σ²_B/n_B)
    """
    n_a, n_b = group_a.shape[0], group_b.shape[0]
    mu_a, mu_b = group_a.mean(axis=0), group_b.mean(axis=0)
    var_a = group_a.var(axis=0, ddof=1)
    var_b = group_b.var(axis=0, ddof=1)
    denom = np.sqrt(var_a / n_a + var_b / n_b)
    denom[denom < 1e-12] = 1e-12
    return (mu_a - mu_b) / denom


# ══════════════════════════════════════════════════════════════════════════
# Plotting
# ══════════════════════════════════════════════════════════════════════════

def plot_corr_vs_time(corr_matrix: np.ndarray, true_rk10: np.ndarray,
                      byte_idx: int = 0, outpath: str = "cpa_correlation_vs_time.png"):
    """Plot correlation vs clock cycle for all 256 key guesses (one byte)."""
    fig, ax = plt.subplots(figsize=(10, 6))

    n_time = corr_matrix.shape[2]
    cycles = np.arange(n_time)

    # Plot all wrong guesses in grey
    for kg in range(256):
        if kg == true_rk10[byte_idx]:
            continue
        ax.plot(cycles, corr_matrix[byte_idx, kg, :],
                color='lightgrey', linewidth=0.3, alpha=0.5)

    # Plot correct guess in red
    correct = true_rk10[byte_idx]
    ax.plot(cycles, corr_matrix[byte_idx, correct, :],
            color='red', linewidth=2.5, label=f'Correct: 0x{correct:02x}')

    ax.axhline(0, color='black', linewidth=0.5)
    ax.axvline(10, color='blue', linewidth=1, linestyle='--', alpha=0.5,
               label='Cycle 10 (last round)')
    ax.set_xlabel('Clock Cycle', fontsize=12)
    ax.set_ylabel('Pearson Correlation', fontsize=12)
    ax.set_title(f'CPA: Correlation vs. Time — Key Byte {byte_idx} '
                 f'(correct = 0x{correct:02x})', fontsize=13)
    ax.legend(fontsize=11)
    ax.set_xticks(range(n_time))
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"  ✓ Saved: {outpath}")


def plot_corr_vs_time_all_bytes(corr_matrix, true_rk10, outpath):
    """4×4 grid showing all 16 key bytes."""
    fig, axes = plt.subplots(4, 4, figsize=(18, 14))
    n_time = corr_matrix.shape[2]
    cycles = np.arange(n_time)

    for byte_idx in range(16):
        ax = axes[byte_idx // 4, byte_idx % 4]
        for kg in range(256):
            if kg == true_rk10[byte_idx]:
                continue
            ax.plot(cycles, corr_matrix[byte_idx, kg, :],
                    color='lightgrey', linewidth=0.2, alpha=0.4)
        correct = true_rk10[byte_idx]
        ax.plot(cycles, corr_matrix[byte_idx, correct, :],
                color='red', linewidth=1.5)
        ax.set_title(f'Byte {byte_idx}: 0x{correct:02x}', fontsize=9)
        ax.axvline(10, color='blue', linewidth=0.5, linestyle='--', alpha=0.5)
        ax.set_xticks([0, 5, 10])
        ax.tick_params(labelsize=7)

    fig.suptitle('CPA Correlation vs. Time — All 16 Key Bytes', fontsize=14, y=1.01)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  ✓ Saved: {outpath}")


def plot_convergence(trace_counts, pge, outpath):
    """PGE (Partial Guessing Entropy) vs number of traces."""
    fig, ax = plt.subplots(figsize=(10, 6))

    for byte_idx in range(16):
        ax.plot(trace_counts, pge[byte_idx], linewidth=1.2,
                label=f'Byte {byte_idx}')

    ax.set_xlabel('Number of Traces', fontsize=12)
    ax.set_ylabel('Partial Guessing Entropy (PGE)', fontsize=12)
    ax.set_title('CPA: Key Byte Convergence (PGE = 0 means recovered)', fontsize=13)
    ax.legend(fontsize=7, ncol=4, loc='upper right')
    ax.set_ylim(-1, 20)
    ax.axhline(0, color='green', linewidth=1, linestyle='--', alpha=0.7)
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"  ✓ Saved: {outpath}")


def plot_tvla(t_values: np.ndarray, outpath: str):
    """Plot TVLA Welch's t-test per clock cycle."""
    fig, ax = plt.subplots(figsize=(10, 6))
    n_time = len(t_values)
    cycles = np.arange(n_time)

    colors = ['red' if abs(t) > 4.5 else 'steelblue' for t in t_values]
    bars = ax.bar(cycles, t_values, color=colors, edgecolor='black', linewidth=0.5)

    ax.axhline(4.5, color='red', linewidth=1.5, linestyle='--',
               label='Threshold: |t| = 4.5')
    ax.axhline(-4.5, color='red', linewidth=1.5, linestyle='--')
    ax.axhline(0, color='black', linewidth=0.5)

    ax.set_xlabel('Clock Cycle', fontsize=12)
    ax.set_ylabel("Welch's t-statistic", fontsize=12)
    ax.set_title("TVLA (Fixed-vs-Random) — Unpatched AES-128", fontsize=13)
    ax.set_xticks(range(n_time))
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3, axis='y')

    # Annotate max |t|
    max_t_idx = np.argmax(np.abs(t_values))
    max_t_val = t_values[max_t_idx]
    ax.annotate(f'max |t| = {abs(max_t_val):.1f}\n@ cycle {max_t_idx}',
                xy=(max_t_idx, max_t_val),
                xytext=(max_t_idx + 1.5, max_t_val * 0.8),
                fontsize=10, color='darkred',
                arrowprops=dict(arrowstyle='->', color='darkred'))

    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt.close(fig)
    print(f"  ✓ Saved: {outpath}")


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    os.makedirs(PLOT_DIR, exist_ok=True)

    # ── Load traces ─────────────────────────────────────────────────────
    print("Loading traces from:", TRACE_DIR)
    ct, tr, secret_key = load_traces()
    print(f"  CPA traces: {tr.shape[0]} × {tr.shape[1]} time samples")
    print(f"  Secret key: {bytes(secret_key).hex()}")

    # ── Compute true Round Key 10 for validation ────────────────────────
    from generate_traces import key_expand
    rk = list(secret_key)
    for r in range(1, 11):
        rk = key_expand(rk, r)
    true_rk10 = np.array(rk, dtype=np.uint8)
    print(f"  True RK10:  {bytes(true_rk10).hex()}")

    # ── Run CPA ─────────────────────────────────────────────────────────
    recovered_rk10, corr_matrix, _ = cpa_attack(ct, tr)

    # Validate
    print(f"\n   Recovered RK10: {bytes(recovered_rk10).hex()}")
    print(f"   True      RK10: {bytes(true_rk10).hex()}")

    all_correct = np.all(recovered_rk10 == true_rk10)
    for i in range(16):
        status = "✓" if recovered_rk10[i] == true_rk10[i] else "✗"
        peak = np.max(np.abs(corr_matrix[i, recovered_rk10[i], :]))
        print(f"   Byte {i:2d}: guess=0x{recovered_rk10[i]:02x}  "
              f"true=0x{true_rk10[i]:02x}  "
              f"|r|={peak:.4f}  {status}")

    # Recover master key
    recovered_master = recover_master_key(list(recovered_rk10))
    print(f"\n   Recovered Master Key: {bytes(recovered_master).hex()}")
    print(f"   True     Master Key:  {bytes(secret_key).hex()}")
    if bytes(recovered_master) == bytes(secret_key):
        print("   >>> MASTER KEY RECOVERED SUCCESSFULLY <<<")
    else:
        print("   >>> KEY RECOVERY FAILED <<<")

    # ── Plot: Correlation vs Time ───────────────────────────────────────
    print("\nGenerating plots...")
    plot_corr_vs_time(corr_matrix, true_rk10, byte_idx=0,
                      outpath=os.path.join(PLOT_DIR, "cpa_correlation_vs_time_byte0.png"))
    plot_corr_vs_time_all_bytes(corr_matrix, true_rk10,
                                outpath=os.path.join(PLOT_DIR, "cpa_correlation_vs_time_all.png"))

    # ── Plot: Convergence (PGE vs #traces) ──────────────────────────────
    print("Computing convergence curves (PGE vs #traces)...")
    tc, pge = compute_convergence(ct, tr, true_rk10)
    plot_convergence(tc, pge,
                     outpath=os.path.join(PLOT_DIR, "cpa_convergence_pge.png"))

    # Find min traces needed for full recovery
    for ti, tc_val in enumerate(tc):
        if np.all(pge[:, ti] == 0):
            print(f"  → Full 16-byte recovery at ≤ {tc_val} traces")
            break

    # ── TVLA ────────────────────────────────────────────────────────────
    print("\n── TVLA (Welch's t-test) ──")
    tvla_fixed = np.load(os.path.join(TRACE_DIR, "tvla_fixed_traces.npy"))
    tvla_rand  = np.load(os.path.join(TRACE_DIR, "tvla_rand_traces.npy"))
    print(f"   Fixed-PT group: {tvla_fixed.shape[0]} traces")
    print(f"   Random-PT group: {tvla_rand.shape[0]} traces")

    t_values = welch_ttest(tvla_fixed, tvla_rand)
    print(f"   t-values per cycle: {np.array2string(t_values, precision=2, separator=', ')}")
    print(f"   Max |t| = {np.max(np.abs(t_values)):.2f} at cycle {np.argmax(np.abs(t_values))}")

    leaking_cycles = np.where(np.abs(t_values) > 4.5)[0]
    if len(leaking_cycles) > 0:
        print(f"   LEAKING cycles (|t| > 4.5): {list(leaking_cycles)}")
    else:
        print(f"   No leaking cycles (|t| < 4.5 everywhere)")

    plot_tvla(t_values, outpath=os.path.join(PLOT_DIR, "tvla_unpatched.png"))

    # ── Summary ─────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"STAGE 2A RESULTS — Unpatched AES-128")
    print(f"{'='*60}")
    print(f"  CPA Key Recovery:     {'SUCCESS' if all_correct else 'PARTIAL'}")
    print(f"  All 16 bytes (PGE=0): {'YES' if all_correct else 'NO'}")
    print(f"  Recovered Master Key: {bytes(recovered_master).hex()}")
    print(f"  TVLA Max |t|:         {np.max(np.abs(t_values)):.1f}")
    print(f"  TVLA Leaking Cycles:  {list(leaking_cycles)}")
    print(f"  Plots saved to:       {PLOT_DIR}/")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
