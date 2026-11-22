# synth_patched.tcl — Vivado Batch Script for Stage 2 Patched AES-128
# Target: Nexys 4 DDR (xc7a100tcsg324-1)

set output_dir "/home/abhi/Desktop/Hardsec/results/vivado_reports/patched"
file mkdir $output_dir

# Read RTL files
read_verilog -sv "/home/abhi/Desktop/Hardsec/rtl/stage1_unpatched/aes_sbox.sv"
read_verilog -sv "/home/abhi/Desktop/Hardsec/rtl/stage1_unpatched/aes_mixcolumns.sv"
read_verilog -sv "/home/abhi/Desktop/Hardsec/rtl/stage1_unpatched/aes_key_expand.sv"
read_verilog -sv "/home/abhi/Desktop/Hardsec/rtl/stage1_unpatched/uart_rx.sv"
read_verilog -sv "/home/abhi/Desktop/Hardsec/rtl/stage1_unpatched/uart_tx.sv"
read_verilog -sv "/home/abhi/Desktop/Hardsec/rtl/stage2_patched/prng_lfsr.sv"
read_verilog -sv "/home/abhi/Desktop/Hardsec/rtl/stage2_patched/aes_masked_sbox.sv"
read_verilog -sv "/home/abhi/Desktop/Hardsec/rtl/stage2_patched/aes128_masked_core.sv"
read_verilog -sv "/home/abhi/Desktop/Hardsec/rtl/stage2_patched/nexys4ddr_patched_top.sv"

# Read Constraints
read_xdc "/home/abhi/Desktop/Hardsec/constraints/nexys4ddr.xdc"

# Synthesis
synth_design -top nexys4ddr_patched_top -part xc7a100tcsg324-1
report_utilization -file "$output_dir/utilization_synth.rpt"

# Opt Design
opt_design

# Place Design
place_design
report_utilization -file "$output_dir/utilization_placed.rpt"

# Route Design
route_design

# Generate Reports
report_utilization -file "$output_dir/utilization_routed.rpt"
report_timing_summary -file "$output_dir/timing_summary_routed.rpt"
report_power -file "$output_dir/power_routed.rpt"
report_drc -file "$output_dir/drc_routed.rpt"

# Write Checkpoint
write_checkpoint -force "$output_dir/nexys4ddr_patched_routed.dcp"

puts "Synthesis and Implementation for Patched Design COMPLETE!"
exit
