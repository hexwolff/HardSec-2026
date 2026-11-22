# Project Context: HardSec 2026 — "Break-the-Cipher" Hackathon

## 1. Hackathon Overview & Hard Deadlines
- **Event:** HardSec 2026 · Side-Channel Analysis ("Break-the-Cipher: Build it, then break it")
- **Submission Deadline:** **5:00 PM IST, 22 November 2026** (strict; late submissions are not evaluated).
- **Target Hardware:** Digilent **Nexys 4 DDR** FPGA board (Xilinx Artix-7, part number `XC7A100T-1CSG324C` / Vivado part `xc7a100tcsg324-1`).
- **Allowed Tools & Languages:** Vivado, VS Code, Jupyter Notebook, Google Colab, HLS; SystemVerilog, Verilog, Python, C.
- **Reference SCA Repository:** `https://github.com/newaetech/chipwhisperer-jupyter`

---

## 2. Official Stages, Rules & Judging Criteria

### Stage 1: Design & Validate
- **Task:** Design and validate any cryptographic algorithm (symmetric, asymmetric, or hash).
- **Judging Criteria:** Best **speed, area, or power** (**hardware designs are strongly preferred**).

### Stage 2: Break & Patch
- **Task:** Find a side-channel vulnerability in our own Stage 1 design (timing, power, fault, DFT, or cache leakage—anything dependent on the secret key) and propose/implement a patch.
- **Note on Execution:** Stage 2 can be largely simulation-based using the ChipWhisperer methodology/notebooks; a live physical hardware demonstration on the Nexys 4 DDR is optional and treated as a stretch goal only after simulation & verification are 100% complete.
- **Deliverables:** The exact vulnerability, how we discovered/exploited it, and the fix.
- **Judging Criteria:** **Quality of the proposed patch** (effectiveness of mitigation + engineering rigor + PPA overhead analysis).

### Mandatory Rules & Ethics
1. **Original Work & Citations:** All submitted code must be our team's own. Any open-source references, standard specifications (e.g., NIST FIPS 197), or SCA scripts (e.g., `chipwhisperer-jupyter`) MUST be explicitly cited in the documentation/PDF report. Uncredited work leads to disqualification.
2. **AI Tool Disclosure:** Maintain a clear note of AI assistance used so it can be transparently declared in the report.
3. **Ethical Conduct:** Attack ONLY our own Stage 1 design.
4. **Final Submission Package (Single submission via Google Form / Drive):**
   - Complete source code (RTL, testbenches, constraints, Python/Jupyter SCA scripts).
   - Results with clear screenshots (simulation waveforms, Vivado utilization/timing/power reports, FPGA UART/ILA output, CPA correlation plots, TVLA t-test plots).
   - A clean **PDF report** covering: what we built, what we obtained (quantitative PPA + SCA results), how the patch works, and all references used.

---

## 3. Technical Execution Plan

### Stage 1 Plan: Lean, From-Scratch Hardware AES-128 (SystemVerilog)
We are building an **encryption-only, iterative 128-bit AES-128 core from scratch in SystemVerilog**, optimized for low area (LUTs/FFs), high $f_{\max}$, and low dynamic power on the Artix-7 (`xc7a100tcsg324-1`).

#### Architecture Specifications
- **Datapath:** Iterative 128-bit round architecture — **1 round per clock cycle (11 cycles per 128-bit block)**:
  - Cycle 0: Initial `AddRoundKey` (`plaintext ^ key_0`), latch into `state_reg`.
  - Cycles 1–9: `SubBytes` -> `ShiftRows` -> `MixColumns` -> `AddRoundKey`, latch into `state_reg`.
  - Cycle 10: Final round (`SubBytes` -> `ShiftRows` -> `AddRoundKey`, skipping `MixColumns`), latch into `state_reg` and assert `done`.
- **On-the-Fly Key Expansion:** Compute the next 128-bit round key in parallel with each encryption round using a single 128-bit `key_reg` and 4 S-boxes (eliminates round-key RAM/register bloat and eliminates key-setup latency).
- **S-Box Strategy:** 20 combinational S-boxes total (16 for state, 4 for key schedule), implemented cleanly to map well onto Artix-7 `LUT6` primitives (optionally evaluate LUT-based vs. Canright composite-field S-box if area optimization is needed).
- **MixColumns:** Pure combinational $GF(2^8)$ `xtime` arithmetic (no DSPs required).
- **Interface:** Clean `clk`, `rst_n`, `start`, `plaintext[127:0]`, `key[127:0]`, `ciphertext[127:0]`, `busy`, `done`.

#### Stage 1 Validation & FPGA Deployment
1. **Functional Verification:**
   - Verify against official **NIST FIPS 197** test vectors (Appendix B & C.1).
   - Run automated randomized regression (1,000+ random plaintexts/keys) in Verilator or Vivado Simulator against a Python golden reference (`pycryptodome` or `cryptography`).
2. **Vivado Synthesis & Implementation (`xc7a100tcsg324-1`):**
   - Synthesize, place & route, and extract exact metrics: **LUTs, FFs, Slices, BRAM/DSP (0), WNS / $f_{\max}$ (MHz), Latency (cycles), Throughput (Mbps), and Dynamic/Total Power (mW)**.
3. **Nexys 4 DDR Hardware Validation:**
   - Wrap the AES-128 core in a lightweight **UART TX/RX** (or Vivado **VIO/ILA**) top-level module with `.xdc` constraints for the Nexys 4 DDR (`100 MHz` clock, USB-UART bridge).
   - Program the board, send NIST test vectors from a Python host script, verify matching ciphertext on real hardware, and capture screenshots/photos.

---

### Stage 2 Plan: Side-Channel Attack (CPA) & Hardware Patch

#### Phase 2A — Breaking Stage 1 (Correlation Power Analysis)
We align our attack directly with `chipwhisperer-jupyter` (`courses/sca201/Lab 2_2 - CPA on Hardware AES Implementation.ipynb`):
- **Target Leakage Mechanism:** Because our iterative hardware AES overwrites the same 128-bit `state_reg` every clock cycle, dynamic CMOS switching power is proportional to the **Hamming Distance (HD)** between consecutive register states: $P(t) \propto \text{HW}(S_t \oplus S_{t-1}) + \mathcal{N}(0, \sigma^2)$.
- **Attack Point (Round 10 — `last_round_state_diff`):**
  - Round 10 has no `MixColumns`, so each ciphertext byte maps 1-to-1 to a single Round 9 state byte via `InvShiftRows` and `InvSubBytes`.
  - For each key byte guess $k_{10, i} \in [0, 255]$:
    - $st_{10} = \text{CT}[\text{InvShiftRows}^{-1}(i)]$
    - $st_9 = \text{InvSubBytes}(\text{CT}[i] \oplus k_{10, i})$
    - Hypothetical leakage: $H = \text{HW}(st_9 \oplus st_{10})$
  - Correlate $H$ against simulated power traces using Pearson correlation across all 16 bytes to recover **Round Key 10**, then invert the AES-128 key schedule to recover the **128-bit Master Key**.
- **Trace Generation Pipeline:**
  - Simulate $N = 1,000\text{–}2,000$ encryptions with a fixed secret key and random plaintexts.
  - Extract cycle-by-cycle toggle counts / Hamming Distance across all design registers (prefer **post-synthesis gate-level VCD/SAIF toggle extraction** from Vivado for realism, or RTL full-register toggle logging + calibrated Gaussian noise $\sigma$ as a fast baseline).
  - Run CPA in a clean Jupyter Notebook and generate:
    1. **Correlation vs. Time (Clock Cycle)** plot showing the sharp spike at Cycle 10.
    2. **Correlation vs. Number of Traces** plot showing key convergence (e.g., full 16-byte recovery in < 500 traces).
    3. **Byte-by-byte key recovery table** (PGE = 0 for all 16 bytes) + recovered master key match.
- **TVLA Baseline (Welch's t-test):**
  - Collect Fixed-vs-Random plaintext trace sets ($N \ge 2,000$ each) and compute Welch's $t$-statistic per clock cycle.
  - Show massive leakage ($\vert{}t\vert{} \gg 4.5$) on the unpatched Stage 1 design.

#### Phase 2B — Patching Stage 1 (Countermeasure Design)
To maximize Stage 2 judging score ("best proposed patch"), implement **First-Order Boolean Masking** as our primary defense:
- **Primary Patch: First-Order Boolean Masked AES-128**
  - Instantiate an on-chip **PRNG** (e.g., 128-bit or multi-tap LFSR / Trivium-lite / Xoshiro seeded per run) to generate fresh random masks ($m_{in}, m_{out}$ / 128-bit state mask $M$) for every encryption.
  - Mask the state before Cycle 0: $S' = S \oplus M$.
  - Propagate the mask cleanly through linear layers (`AddRoundKey`, `ShiftRows`, `MixColumns`) in parallel without unmasking.
  - Protect the non-linear `SubBytes` layer using either:
    - **Approach A (Recommended for reliability under tight deadline):** Recomputed masked S-box / table masking $S_{\text{masked}}(x \oplus m_{in}) = S(x) \oplus m_{out}$ refreshed per encryption, OR
    - **Approach B (Strongest hardware masking):** Masked composite-field S-box in $GF(((2^2)^2)^2)$ with registered stages to prevent combinational glitches.
  - Unmask only at the final output register (`ciphertext = state_masked ^ final_mask`).
- **Optional Complementary / Fallback Hiding Layer (if time permits or as defense-in-depth):**
  - Register precharging (zeroing/randomizing state between rounds) + random dummy clock cycles to break temporal alignment and suppress HD transitions.

#### Phase 2C — Proving the Patch Works & PPA Comparison
1. **Functional Equivalence:** Re-verify the patched RTL against all NIST FIPS 197 vectors and 1,000+ random vectors.
2. **Attack Resistance Verification:** Run the **exact same CPA script** (and higher trace counts, e.g., $N = 5,000\text{–}10,000$) on traces from the patched design. Demonstrate that:
   - The true key byte correlation collapses into the noise floor (key recovery fails; PGE remains high).
   - Fixed-vs-Random **Welch's t-test (TVLA)** stays within $\vert{}t\vert{} < 4.5$ across all clock cycles.
3. **PPA vs. Security Tradeoff Table:** Synthesize & implement the patched core in Vivado for `xc7a100tcsg324-1` and produce a side-by-side comparison table (Stage 1 Unpatched vs. Stage 2 Patched: LUTs, FFs, $f_{\max}$, Latency, Throughput, Power, CPA Key Recovery, Max $\vert{}t\vert{}$-value).

#### Phase 2D — Optional Hardware Stretch Goal (Strictly Only After 2A–2C Are Complete)
- Deploy the patched AES-128 core on the Nexys 4 DDR over UART, or implement a simple on-chip Ring Oscillator (RO) / voltage-droop sensor experiment on the Artix-7. Do NOT let this delay simulation, patching, or the PDF report.

---

## 4. Recommended Repository Structure
```text
hardsec-aes128/
├── CONTEXT.md
├── rtl/
│   ├── stage1_unpatched/
│   │   ├── aes_sbox.sv
│   │   ├── aes_mixcolumns.sv
│   │   ├── aes_key_expand.sv
│   │   ├── aes128_core.sv
│   │   └── nexys4ddr_top.sv        # UART / VIO wrapper for FPGA
│   └── stage2_patched/
│       ├── prng_lfsr.sv
│       ├── aes_masked_sbox.sv
│       ├── aes128_masked_core.sv
│       └── nexys4ddr_patched_top.sv
├── tb/
│   ├── tb_aes128_unpatched.sv      # NIST + random + trace logger
│   └── tb_aes128_patched.sv        # NIST + random + trace logger
├── constraints/
│   └── nexys4ddr.xdc
├── sca/
│   ├── generate_traces.py          # Automates sim & builds .npy trace datasets
│   ├── cpa_attack_and_tvla.ipynb   # ChipWhisperer-style CPA + Welch's t-test
│   └── uart_fpga_verify.py         # Sends NIST vectors to Nexys 4 DDR
├── results/
│   ├── vivado_reports/             # Util, timing, power reports + screenshots
│   └── plots/                      # CPA & TVLA PNG figures for PDF report
└── report/
    └── HardSec2026_Report.md       # Source for final PDF report + citations


