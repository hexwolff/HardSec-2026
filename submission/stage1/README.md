# Stage 1 — AES-128 Hardware Implementation

**HardSec 2026 | Team hexwolff | B Abhilash (HS26-0030)**

## Overview
Round-iterative AES-128 encryption core in SystemVerilog, deployed on Nexys 4 DDR FPGA (xc7a100tcsg324-1) with UART I/O at 115200 baud.

## Directory Structure
```
stage1/
├── rtl/              # SystemVerilog source files
│   ├── aes_sbox.sv           # AES S-Box (BRAM lookup table)
│   ├── aes_mixcolumns.sv     # MixColumns transformation
│   ├── aes_key_expand.sv     # On-the-fly key expansion
│   ├── aes128_core.sv        # AES-128 core (FSM, 11-cycle)
│   ├── uart_rx.sv            # UART receiver (115200 baud)
│   ├── uart_tx.sv            # UART transmitter
│   └── nexys4ddr_top.sv      # FPGA top-level wrapper
├── tb/               # Testbenches
│   ├── tb_aes128_unpatched.sv  # Main testbench (1003 vectors)
│   └── gen_test_vectors.py     # Test vector generator
├── constraints/      # FPGA constraints
│   └── nexys4ddr.xdc          # Pin + timing constraints
├── scripts/          # Python utilities
│   ├── uart_fpga_verify.py    # FPGA UART test automation
│   └── aes_interactive.py     # Interactive UART terminal
├── vivado_reports/   # Vivado post-P&R reports
│   ├── nexys4ddr_top_utilization_placed.rpt
│   ├── nexys4ddr_top_timing_summary_routed.rpt
│   └── nexys4ddr_top_power_routed.rpt
├── results/          # Test output logs
├── docs/             # Architecture documentation
└── media/            # Screenshots & videos (paste here)
```

## Quick Start

### Simulation (iverilog)
```bash
iverilog -g2012 -o sim rtl/*.sv tb/tb_aes128_unpatched.sv
vvp sim
```

### FPGA Test (after programming)
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install pyserial cryptography numpy
python3 scripts/uart_fpga_verify.py
```

## PPA Summary
| Metric | Value |
|--------|-------|
| LUTs | 717 (1.13%) |
| FFs | 1,009 (0.80%) |
| BRAM | 5 tiles (3.70%) |
| fmax | ~129 MHz |
| Total Power | 119 mW |
| Latency | 11 cycles |
