// ============================================================================
// tb_trace_logger.sv — AES-128 Trace Logger for Side-Channel Analysis
//
// Runs N encryptions with a FIXED secret key and RANDOM plaintexts.
// Logs the 128-bit state_reg and key_reg at every clock cycle to a text file,
// enabling Hamming-Distance power modelling for CPA / TVLA.
//
// Output files:
//   traces_state.txt  — cycle-by-cycle state_reg dumps
//   traces_meta.txt   — plaintext, key, ciphertext per encryption
//
// Compile & run:
//   iverilog -g2012 -o tb_trace.vvp \
//     ../rtl/stage1_unpatched/aes_sbox.sv \
//     ../rtl/stage1_unpatched/aes_mixcolumns.sv \
//     ../rtl/stage1_unpatched/aes_key_expand.sv \
//     ../rtl/stage1_unpatched/aes128_core.sv \
//     tb_trace_logger.sv
//   vvp tb_trace.vvp
// ============================================================================

`timescale 1ns / 1ps

module tb_trace_logger;

    // ── Parameters ─────────────────────────────────────────────────────────
    parameter N_TRACES = 2000;
    parameter FIXED_KEY = 128'h2b7e151628aed2a6abf7158809cf4f3c;  // NIST FIPS 197

    // ── Clock / reset / DUT signals ────────────────────────────────────────
    logic         clk;
    logic         rst_n;
    logic         start;
    logic [127:0] plaintext;
    logic [127:0] key;
    logic [127:0] ciphertext;
    logic         busy;
    logic         done;

    initial clk = 0;
    always #5 clk = ~clk;  // 100 MHz

    aes128_core u_dut (
        .clk        (clk),
        .rst_n      (rst_n),
        .start      (start),
        .plaintext  (plaintext),
        .key        (key),
        .ciphertext (ciphertext),
        .busy       (busy),
        .done       (done)
    );

    // ── PRNG for random plaintexts (simple LFSR-based) ─────────────────────
    // We use $urandom for simulation-only randomness.

    // ── File handles ───────────────────────────────────────────────────────
    integer fd_state, fd_meta;
    integer trace_idx;
    integer cycle_in_trace;
    reg [127:0] prev_state;

    // ── Main test sequence ─────────────────────────────────────────────────
    initial begin
        fd_state = $fopen("traces_state.txt", "w");
        fd_meta  = $fopen("traces_meta.txt", "w");

        if (fd_state == 0 || fd_meta == 0) begin
            $display("ERROR: Cannot open output files!");
            $finish;
        end

        // Header
        $fwrite(fd_meta, "# trace_idx plaintext_hex key_hex ciphertext_hex\n");
        $fwrite(fd_state, "# trace_idx cycle state_reg_hex key_reg_hex\n");

        // Reset
        rst_n     = 1'b0;
        start     = 1'b0;
        plaintext = 128'b0;
        key       = FIXED_KEY;
        repeat (5) @(posedge clk);
        rst_n = 1'b1;
        repeat (2) @(posedge clk);

        $display("Starting trace generation: %0d traces with key = %h", N_TRACES, FIXED_KEY);

        for (trace_idx = 0; trace_idx < N_TRACES; trace_idx = trace_idx + 1) begin
            // Generate random plaintext
            plaintext = {$urandom, $urandom, $urandom, $urandom};

            // Start encryption
            @(posedge clk);
            start <= 1'b1;
            @(posedge clk);
            start <= 1'b0;

            // Log state at cycle 0 (initial AddRoundKey result latched on this edge)
            // The state_reg is loaded combinationally on the start cycle, so we
            // need to wait one cycle for it to be registered
            cycle_in_trace = 0;

            // Log cycles 0–10 (the state after each posedge while running)
            while (!done) begin
                @(posedge clk);
                // After this posedge, state_reg contains the result of cycle_in_trace
                $fwrite(fd_state, "%0d %0d %032h %032h\n",
                        trace_idx, cycle_in_trace,
                        u_dut.state_reg, u_dut.key_reg);
                cycle_in_trace = cycle_in_trace + 1;
            end

            // Log metadata
            $fwrite(fd_meta, "%0d %032h %032h %032h\n",
                    trace_idx, plaintext, FIXED_KEY, ciphertext);

            // Progress every 500 traces
            if ((trace_idx + 1) % 500 == 0)
                $display("  ... %0d / %0d traces done", trace_idx + 1, N_TRACES);
        end

        $fclose(fd_state);
        $fclose(fd_meta);
        $display("Trace generation complete: %0d traces written.", N_TRACES);
        $finish;
    end

    // Timeout
    initial begin
        #500000000;  // 500 ms
        $display("FATAL: Global timeout!");
        $finish;
    end

endmodule
