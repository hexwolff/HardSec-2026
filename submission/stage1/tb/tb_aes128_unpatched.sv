// ============================================================================
// Testbench: tb_aes128_unpatched.sv
// Validates aes128_core against:
//   1. NIST FIPS 197 Appendix B test vector
//   2. NIST FIPS 197 Appendix C.1 test vector
//   3. 1000 random plaintext/key pairs (from Python golden reference)
//
// Simulation: iverilog / Verilator / Vivado xsim
// ============================================================================

`timescale 1ns / 1ps

module tb_aes128_unpatched;

    // ========================================================================
    // Clock and reset
    // ========================================================================
    logic         clk;
    logic         rst_n;
    logic         start;
    logic [127:0] plaintext;
    logic [127:0] key;
    logic [127:0] ciphertext;
    logic         busy;
    logic         done;

    // 10 ns period -> 100 MHz
    initial clk = 0;
    always #5 clk = ~clk;

    // ========================================================================
    // DUT instantiation
    // ========================================================================
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

    // ========================================================================
    // Test infrastructure
    // ========================================================================
    integer pass_count;
    integer fail_count;
    integer total_tests;
    integer fd;
    integer scan_ret;

    // For reading hex file
    reg [127:0] file_pt, file_key, file_ct;
    reg [127:0] expected_ct;

    // ========================================================================
    // Task: run one encryption and check result
    // ========================================================================
    task automatic run_encrypt(
        input  [127:0] pt_in,
        input  [127:0] key_in,
        input  [127:0] ct_expected,
        input  string  test_name
    );
        begin
            @(posedge clk);
            plaintext <= pt_in;
            key       <= key_in;
            start     <= 1'b1;
            @(posedge clk);
            start     <= 1'b0;

            // Wait for done (timeout after 20 cycles)
            begin : wait_done
                integer timeout;
                timeout = 0;
                while (!done && timeout < 20) begin
                    @(posedge clk);
                    timeout = timeout + 1;
                end
                if (timeout >= 20) begin
                    $display("FAIL [%s]: Timeout waiting for done!", test_name);
                    fail_count = fail_count + 1;
                    disable wait_done;
                end
            end

            // Check result
            if (ciphertext === ct_expected) begin
                pass_count = pass_count + 1;
            end else begin
                $display("FAIL [%s]:", test_name);
                $display("  PT:       %h", pt_in);
                $display("  KEY:      %h", key_in);
                $display("  Expected: %h", ct_expected);
                $display("  Got:      %h", ciphertext);
                fail_count = fail_count + 1;
            end
            total_tests = total_tests + 1;
        end
    endtask

    // ========================================================================
    // Main test sequence
    // ========================================================================
    initial begin
        // Initialize
        pass_count  = 0;
        fail_count  = 0;
        total_tests = 0;
        rst_n       = 1'b0;
        start       = 1'b0;
        plaintext   = 128'b0;
        key         = 128'b0;

        // Reset for 5 cycles
        repeat (5) @(posedge clk);
        rst_n = 1'b1;
        repeat (2) @(posedge clk);

        $display("============================================================");
        $display("AES-128 Unpatched Core — Functional Verification");
        $display("============================================================");

        // ====================================================================
        // Test 1: NIST FIPS 197, Appendix B
        //   Key:       2b7e151628aed2a6abf7158809cf4f3c
        //   Plaintext: 3243f6a8885a308d313198a2e0370734
        //   Ciphertext:3925841d02dc09fbdc118597196a0b32
        // ====================================================================
        $display("\n--- NIST FIPS 197 Appendix B ---");
        run_encrypt(
            128'h3243f6a8885a308d313198a2e0370734,
            128'h2b7e151628aed2a6abf7158809cf4f3c,
            128'h3925841d02dc09fbdc118597196a0b32,
            "NIST Appendix B"
        );

        // ====================================================================
        // Test 2: NIST FIPS 197, Appendix C.1 (AES-128)
        //   Key:       000102030405060708090a0b0c0d0e0f
        //   Plaintext: 00112233445566778899aabbccddeeff
        //   Ciphertext:69c4e0d86a7b0430d8cdb78070b4c55a
        // ====================================================================
        $display("--- NIST FIPS 197 Appendix C.1 ---");
        run_encrypt(
            128'h00112233445566778899aabbccddeeff,
            128'h000102030405060708090a0b0c0d0e0f,
            128'h69c4e0d86a7b0430d8cdb78070b4c55a,
            "NIST Appendix C.1"
        );

        // ====================================================================
        // Test 3: All-zeros
        // ====================================================================
        $display("--- All-Zeros Test ---");
        run_encrypt(
            128'h00000000000000000000000000000000,
            128'h00000000000000000000000000000000,
            128'h66e94bd4ef8a2c3b884cfa59ca342b2e,
            "All-Zeros"
        );

        // ====================================================================
        // Test 4: 1000 random vectors from Python golden reference
        // ====================================================================
        $display("\n--- Random Vectors (1000) ---");
        fd = $fopen("test_vectors.hex", "r");
        if (fd == 0) begin
            $display("WARNING: Cannot open test_vectors.hex — skipping random tests.");
            $display("         Run: python3 gen_test_vectors.py test_vectors.hex");
        end else begin
            while (!$feof(fd)) begin
                scan_ret = $fscanf(fd, "%h %h %h\n", file_pt, file_key, file_ct);
                if (scan_ret == 3) begin
                    run_encrypt(file_pt, file_key, file_ct, "Random");
                end
            end
            $fclose(fd);
        end

        // ====================================================================
        // Summary
        // ====================================================================
        $display("\n============================================================");
        $display("RESULTS: %0d / %0d passed (%0d failed)",
                 pass_count, total_tests, fail_count);
        if (fail_count == 0)
            $display(">>> ALL TESTS PASSED <<<");
        else
            $display(">>> SOME TESTS FAILED <<<");
        $display("============================================================");

        $finish;
    end

    // Timeout watchdog
    initial begin
        #2000000;  // 2 ms max simulation time
        $display("FATAL: Global simulation timeout!");
        $finish;
    end

endmodule
