# 🛡️ HardSec 2026 — Break-the-Cipher: AES-128 Hardware Security

<div align="center">

**Build it. Break it. Patch it.**

[![FPGA](https://img.shields.io/badge/FPGA-Nexys%204%20DDR-blue)](#)
[![Vivado](https://img.shields.io/badge/Vivado-2025.1-orange)](#)
[![Language](https://img.shields.io/badge/SystemVerilog-IEEE%201800--2017-green)](#)
[![License](https://img.shields.io/badge/License-MIT-yellow)](#)

*AES-128 encryption core in SystemVerilog, deployed on Artix-7 FPGA, broken via Correlation Power Analysis, and patched with first-order Boolean masking.*

</div>

---

## 📋 Problem Statement

> **HardSec 2026** is a hardware security hackathon challenging participants to:
>
> **Stage 1 — Design & Validate:** Implement a cryptographic algorithm in hardware (targeting best speed, area, or power on an FPGA).
>
> **Stage 2 — Break & Patch:** Discover a side-channel vulnerability in your own Stage 1 design, demonstrate the attack, and implement an effective countermeasure. Judged on patch quality, engineering rigor, and PPA overhead analysis.
>
> **Target:** Digilent Nexys 4 DDR FPGA (Xilinx Artix-7, `xc7a100tcsg324-1`)
> **Tools:** Vivado 2025.1, SystemVerilog, Python

---

## 🏗️ Architecture

### Stage 1 — Unpatched AES-128 Core

A **round-iterative** AES-128 encryption engine — one round datapath reused across all 10 rounds + initial AddRoundKey (11 clock cycles per 128-bit block).

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NEXYS 4 DDR TOP                              │
│                                                                     │
│   ┌──────────┐    ┌──────────────────────────────┐    ┌──────────┐ │
│   │  UART RX │───▶│       AES-128 CORE           │───▶│  UART TX │ │
│   │ (115200) │    │                              │    │ (115200) │ │
│   └──────────┘    │  ┌────────┐  ┌───────────┐  │    └──────────┘ │
│        ▲          │  │SubBytes│  │ ShiftRows  │  │         │       │
│        │          │  │ (SBox  │  │            │  │         │       │
│   USB-UART        │  │  ×16)  │──▶│ MixColumns │  │         ▼       │
│   /dev/ttyUSB1    │  └────────┘  └───────────┘  │     USB-UART    │
│                   │       ▲           │          │                  │
│                   │       │     ┌─────▼─────┐   │                  │
│                   │   Round     │ AddRndKey  │   │                  │
│                   │   Control   └───────────┘   │                  │
│                   │   (FSM)          │          │                  │
│                   │       │    ┌─────▼───────┐  │                  │
│                   │       └────│Key Expansion │  │                  │
│                   │            │ (on-the-fly) │  │                  │
│                   │            └──────────────┘  │                  │
│                   └──────────────────────────────┘                  │
│                                                                     │
│   CLK: 100 MHz (E3)         RST: CPU_RESETN (C12)                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Stage 2 — Masked AES-128 Core (Patched)

**First-order Boolean masking** applied to the AES core. A 128-bit LFSR PRNG generates fresh random masks each round. The S-Box lookup table is recomputed with the new mask every round (256 cycles), ensuring all intermediate values processed by hardware are statistically independent of the secret key.

```
┌─────────────────────────────────────────────────────────────────────┐
│                   MASKED AES-128 CORE                               │
│                                                                     │
│   ┌───────────┐                                                     │
│   │ PRNG LFSR │──── 128-bit random mask (refreshed per round)      │
│   │ (128-bit) │                                                     │
│   └─────┬─────┘                                                     │
│         ▼                                                           │
│   ┌─────────────────┐    ┌────────────┐    ┌────────────┐          │
│   │  Masked SubBytes │───▶│  ShiftRows │───▶│  MixCols   │          │
│   │  (table re-init  │    │            │    │            │          │
│   │   256 cyc/round) │    └────────────┘    └────────────┘          │
│   └─────────────────┘                            │                  │
│         ▲                                  ┌─────▼─────┐           │
│         │                                  │ AddRndKey  │           │
│   T[x ⊕ m_in] = S(x) ⊕ m_out            └───────────┘           │
│   (pre-computed masked table)                    │                  │
│                                            ┌─────▼───────┐         │
│                                            │Key Expansion │         │
│                                            └──────────────┘         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Results at a Glance

| Metric | Unpatched | Masked (Patched) |
|---|---|---|
| **CPA Key Recovery** | ✅ 16/16 bytes (PGE=0) | ❌ 0/16 bytes |
| **TVLA Max \|t\|** | ⚠️ 102.5 (FAIL) | ✅ 2.25 (PASS < 4.5) |
| **Traces to Break** | ≤ 420 | > 5,000 (failed) |
| Slice LUTs | 717 (1.13%) | 1,936 (3.05%) |
| Slice Registers | 1,009 (0.80%) | 1,965 (1.55%) |
| Block RAM | 10× RAMB18 (3.70%) | 24× RAMB18 (8.89%) |
| fmax | ~129 MHz | ~125 MHz |
| Latency | 11 cycles | ~2,570 cycles |
| Total Power | 119 mW | 230 mW |

---

## 📁 Repository Structure

```
├── submission/                    ← Final submission package
│   ├── HardSec2026_Report.pdf         Master documentation (8 pages)
│   ├── stage1/                        Stage 1 deliverables
│   │   ├── rtl/                       7 SystemVerilog modules
│   │   ├── tb/                        Testbench + test vector generator
│   │   ├── constraints/               Nexys 4 DDR XDC
│   │   ├── scripts/                   UART verification scripts
│   │   ├── vivado_reports/            Post-P&R Vivado reports
│   │   └── media/                     Demo screenshots & videos
│   └── stage2/                        Stage 2 deliverables
│       ├── rtl/                       9 SystemVerilog modules (masked)
│       ├── tb/                        Masked core testbench
│       ├── sca/                       CPA + TVLA Python scripts
│       ├── vivado_reports/            Post-P&R Vivado reports
│       ├── results/plots/             CPA & TVLA analysis plots
│       └── media/                     Demo screenshots & videos
├── rtl/
│   ├── stage1_unpatched/              Original AES-128 RTL
│   └── stage2_patched/               Masked AES-128 RTL
├── tb/                                Testbenches
├── sca/                               Side-channel analysis scripts
├── constraints/                       FPGA constraint files
├── results/
│   ├── vivado_reports/                Vivado synthesis & implementation reports
│   └── plots/                         CPA correlation, convergence, TVLA plots
└── report/                            Report source files
```

---

## 🚀 Quick Start

### Prerequisites
- **Vivado 2025.1** (for synthesis & FPGA deployment)
- **Python 3.10+** with `numpy`, `matplotlib`, `cryptography`, `pyserial`
- **iverilog** (optional, for simulation without Vivado)

### Run Simulation
```bash
# Stage 1 — Unpatched AES-128
iverilog -g2012 -o sim_s1 rtl/stage1_unpatched/*.sv tb/tb_aes128_unpatched.sv
vvp sim_s1
# Expected: 1003/1003 PASSED

# Stage 2 — Masked AES-128
iverilog -g2012 -o sim_s2 rtl/stage2_patched/*.sv rtl/stage1_unpatched/aes_sbox.sv \
  rtl/stage1_unpatched/aes_mixcolumns.sv rtl/stage1_unpatched/aes_key_expand.sv \
  rtl/stage1_unpatched/uart_rx.sv rtl/stage1_unpatched/uart_tx.sv tb/tb_aes128_patched.sv
vvp sim_s2
# Expected: 103/103 PASSED
```

### Run CPA Attack
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install numpy matplotlib cryptography

# Generate power traces & run CPA + TVLA (unpatched)
python3 sca/generate_traces.py
python3 sca/cpa_attack_and_tvla.py

# Generate traces & verify masking defeats CPA (patched)
python3 sca/generate_masked_traces.py
python3 sca/cpa_and_tvla_patched.py
```

### FPGA Deployment
```bash
# After programming the bitstream via Vivado:
pip install pyserial
python3 sca/aes_interactive.py        # Interactive UART terminal
python3 sca/uart_fpga_verify.py       # Automated 1003-vector test
```

---

## 📚 References

- **NIST FIPS 197** — Advanced Encryption Standard (AES), 2001
- **Brier, Clavier, Olivier** — "Correlation Power Analysis with a Leakage Model", CHES 2004
- **Goodwill, Jun, Jaffe, Rohatgi** — "A Testing Methodology for Side-Channel Resistance Validation", NIST 2011 (TVLA)
- **Herbst, Oswald, Mangard** — "An AES Smart Card Implementation Resistant to Power Analysis Attacks", ACNS 2006
- **ChipWhisperer** — [chipwhisperer-jupyter](https://github.com/newaetech/chipwhisperer-jupyter) (CPA methodology reference)
- **Digilent** — [Nexys 4 DDR Reference Manual](https://digilent.com/reference/programmable-logic/nexys-4-ddr/reference-manual)

---

## 👤 Team

| | |
|---|---|
| **Name** | B Abhilash |
| **Reg ID** | HS26-0030 |
| **Team** | hexwolff |
| **Team Size** | 1 (Solo) |

---

<div align="center">
<sub>Built for HardSec 2026 · November 2026</sub>
</div>
