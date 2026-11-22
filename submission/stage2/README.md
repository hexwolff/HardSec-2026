# Stage 2 — Side-Channel Attack & Countermeasure

**HardSec 2026 | Team hexwolff | B Abhilash (HS26-0030)**

## Overview
1. **CPA Attack** — Correlation Power Analysis recovers all 16 key bytes from the unpatched AES-128 core
2. **Masking Countermeasure** — First-order Boolean masking prevents key recovery
3. **Security Validation** — TVLA confirms leakage elimination

## Directory Structure
```
stage2/
├── rtl/              # Masked AES-128 SystemVerilog source
│   ├── prng_lfsr.sv           # 128-bit Galois LFSR PRNG
│   ├── aes_masked_sbox.sv     # Masked S-Box (table re-init)
│   ├── aes128_masked_core.sv  # First-order masked AES core
│   ├── nexys4ddr_patched_top.sv # FPGA wrapper for masked core
│   ├── aes_sbox.sv            # Shared: original S-Box
│   ├── aes_mixcolumns.sv      # Shared: MixColumns
│   ├── aes_key_expand.sv      # Shared: Key expansion
│   ├── uart_rx.sv             # Shared: UART RX
│   └── uart_tx.sv             # Shared: UART TX
├── tb/               # Testbenches
│   └── tb_aes128_patched.sv   # Masked core testbench (103 vectors)
├── sca/              # Side-channel analysis scripts
│   ├── generate_traces.py         # Unpatched trace generation
│   ├── generate_masked_traces.py  # Masked trace generation
│   ├── cpa_attack_and_tvla.py     # CPA + TVLA on unpatched
│   ├── cpa_and_tvla_patched.py    # CPA + TVLA on masked
│   └── cpa_live_demo.py          # Interactive CPA demo
├── vivado_reports/   # Vivado post-P&R reports (masked)
│   ├── utilization_placed.rpt
│   ├── timing_summary_routed.rpt
│   └── power_routed.rpt
├── results/plots/    # Analysis output plots
│   ├── cpa_correlation_vs_time_byte0.png
│   ├── cpa_convergence_pge.png
│   ├── cpa_convergence_pge_patched.png
│   ├── tvla_unpatched.png
│   ├── tvla_patched.png
│   └── tvla_comparison_unpatched_vs_patched.png
├── docs/             # Approach documentation
└── media/            # Screenshots & videos (paste here)
```

## Running the CPA Attack
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install numpy matplotlib cryptography

# Generate power traces (unpatched)
python3 sca/generate_traces.py

# Run CPA attack + TVLA
python3 sca/cpa_attack_and_tvla.py

# Generate masked traces & verify countermeasure
python3 sca/generate_masked_traces.py
python3 sca/cpa_and_tvla_patched.py
```

## Key Results
| Metric | Unpatched | Masked |
|--------|-----------|--------|
| CPA Key Recovery | 16/16 bytes | 0/16 bytes |
| TVLA Max |t| | 102.5 (FAIL) | 2.25 (PASS) |
| Traces for attack | ≤420 | >5000 (failed) |
| LUTs | 717 | 1,936 |
| Total Power | 119 mW | 230 mW |
