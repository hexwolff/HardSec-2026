## =============================================================================
## HardSec 2026 — AES-128 Unpatched Core — Nexys 4 DDR Constraints
## =============================================================================
## Pin locations from Digilent Nexys-4-DDR-Master.xdc (Rev. C board).
## Target FPGA: Xilinx Artix-7  xc7a100tcsg324-1
## =============================================================================

## ── 100 MHz System Clock ───────────────────────────────────────────────────
set_property -dict { PACKAGE_PIN E3  IOSTANDARD LVCMOS33 } [get_ports CLK100MHZ]
create_clock -name sys_clk -period 10.000 -waveform {0 5} [get_ports CLK100MHZ]

## ── CPU Reset Button (active-low, active press = logic 0) ──────────────────
set_property -dict { PACKAGE_PIN C12 IOSTANDARD LVCMOS33 } [get_ports CPU_RESETN]

## ── USB-UART Bridge (directly on board) ────────────────────────────────────
## UART_TXD_IN  = PC's TX → FPGA's RX  (active-high, idle-high)
## UART_RXD_OUT = FPGA's TX → PC's RX
set_property -dict { PACKAGE_PIN C4  IOSTANDARD LVCMOS33 } [get_ports UART_TXD_IN]
set_property -dict { PACKAGE_PIN D4  IOSTANDARD LVCMOS33 } [get_ports UART_RXD_OUT]

## ── LEDs ───────────────────────────────────────────────────────────────────
set_property -dict { PACKAGE_PIN H17 IOSTANDARD LVCMOS33 } [get_ports {LED[0]}]
set_property -dict { PACKAGE_PIN K15 IOSTANDARD LVCMOS33 } [get_ports {LED[1]}]
set_property -dict { PACKAGE_PIN J13 IOSTANDARD LVCMOS33 } [get_ports {LED[2]}]
set_property -dict { PACKAGE_PIN N14 IOSTANDARD LVCMOS33 } [get_ports {LED[3]}]
set_property -dict { PACKAGE_PIN R18 IOSTANDARD LVCMOS33 } [get_ports {LED[4]}]
set_property -dict { PACKAGE_PIN V17 IOSTANDARD LVCMOS33 } [get_ports {LED[5]}]
set_property -dict { PACKAGE_PIN U17 IOSTANDARD LVCMOS33 } [get_ports {LED[6]}]
set_property -dict { PACKAGE_PIN U16 IOSTANDARD LVCMOS33 } [get_ports {LED[7]}]
set_property -dict { PACKAGE_PIN V16 IOSTANDARD LVCMOS33 } [get_ports {LED[8]}]
set_property -dict { PACKAGE_PIN T15 IOSTANDARD LVCMOS33 } [get_ports {LED[9]}]
set_property -dict { PACKAGE_PIN U14 IOSTANDARD LVCMOS33 } [get_ports {LED[10]}]
set_property -dict { PACKAGE_PIN T16 IOSTANDARD LVCMOS33 } [get_ports {LED[11]}]
set_property -dict { PACKAGE_PIN V15 IOSTANDARD LVCMOS33 } [get_ports {LED[12]}]
set_property -dict { PACKAGE_PIN V14 IOSTANDARD LVCMOS33 } [get_ports {LED[13]}]
set_property -dict { PACKAGE_PIN V12 IOSTANDARD LVCMOS33 } [get_ports {LED[14]}]
set_property -dict { PACKAGE_PIN V11 IOSTANDARD LVCMOS33 } [get_ports {LED[15]}]

## ── Timing Exceptions ─────────────────────────────────────────────────────
## The reset button and UART RX are asynchronous inputs (synchronised inside
## the design); UART TX and LEDs are slow outputs — no I/O timing needed.
set_false_path -from [get_ports {CPU_RESETN UART_TXD_IN}]
set_false_path -to   [get_ports {UART_RXD_OUT LED[*]}]

## ── Configuration ─────────────────────────────────────────────────────────
set_property CFGBVS VCCO                      [current_design]
set_property CONFIG_VOLTAGE 3.3               [current_design]
set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 1  [current_design]
set_property BITSTREAM.CONFIG.CONFIGRATE 33   [current_design]
set_property BITSTREAM.GENERAL.COMPRESS TRUE  [current_design]
