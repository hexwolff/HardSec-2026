`timescale 1ns / 1ps

module tb_debug_masked;
    logic         clk;
    logic         rst_n;
    logic         start;
    logic [127:0] plaintext;
    logic [127:0] key;
    logic [127:0] prng_seed;
    logic [127:0] ciphertext;
    logic         busy;
    logic         done;

    aes128_masked_core u_dut (
        .clk        (clk),
        .rst_n      (rst_n),
        .start      (start),
        .plaintext  (plaintext),
        .key        (key),
        .prng_seed  (prng_seed),
        .ciphertext (ciphertext),
        .busy       (busy),
        .done       (done)
    );

    initial clk = 0;
    always #5 clk = ~clk;

    initial begin
        rst_n = 0;
        start = 0;
        plaintext = 128'h3243f6a8885a308d313198a2e0370734;
        key       = 128'h2b7e151628aed2a6abf7158809cf4f3c;
        prng_seed = 128'hdeadbeefcafebabe123456789abcdef0;

        #20;
        rst_n = 1;
        #20;

        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;

        // Monitor state transitions
        while (!done) begin
            @(posedge clk);
            if (u_dut.fsm_state == 3'd5) begin // S_ROUND_CALC
                $display("--- Round %0d ---", u_dut.round_cnt);
                $display("sbox0 m_in_reg:    %h", u_dut.gen_masked_sbox[0].u_msbox.m_in_reg);
                $display("sbox0 m_out_reg:   %h", u_dut.gen_masked_sbox[0].u_msbox.m_out_reg);
                $display("core mask_out byte0:%h", u_dut.mask_out_reg[127:120]);
                $display("sbox0 in byte:     %h (unmasked: %h)", u_dut.state_reg[127:120], u_dut.state_reg[127:120] ^ u_dut.gen_masked_sbox[0].u_msbox.m_in_reg);
                $display("sbox0 out byte:    %h", u_dut.gen_masked_sbox[0].u_msbox.data_out);
                $display("sbox0 out unmasked:%h (expected d4 in r1)", u_dut.gen_masked_sbox[0].u_msbox.data_out ^ u_dut.mask_out_reg[127:120]);
                $display("unmasked_state:    %h", u_dut.state_reg ^ u_dut.mask_reg);
            end
        end

        @(posedge clk);
        $display("=================================");
        $display("Ciphertext: %h", ciphertext);
        $display("Expected:   3925841d02dc09fbdc118597196a0b32");
        if (ciphertext == 128'h3925841d02dc09fbdc118597196a0b32)
            $display(">>> TEST PASSED! <<<");
        else
            $display(">>> TEST FAILED! <<<");
        $finish;
    end
endmodule
