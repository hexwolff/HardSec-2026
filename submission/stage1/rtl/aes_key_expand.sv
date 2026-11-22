// ============================================================================
// AES-128 On-the-Fly Key Expansion
// Per NIST FIPS 197, Section 5.2 — Key Expansion
//
// Computes the NEXT round key from the current round key.
// Pure combinational logic — the top-level state machine registers key_out.
//
// Key word layout (FIPS 197 §5.2, Figure 11):
//   w[0] = key_in[127:96]
//   w[1] = key_in[95:64]
//   w[2] = key_in[63:32]
//   w[3] = key_in[31:0]
//
// Round key derivation (FIPS 197 §5.2, Eq. 5.2):
//   new_w[0] = old_w[0] ^ SubWord(RotWord(old_w[3])) ^ Rcon[round]
//   new_w[1] = old_w[1] ^ new_w[0]
//   new_w[2] = old_w[2] ^ new_w[1]
//   new_w[3] = old_w[3] ^ new_w[2]
// ============================================================================

module aes_key_expand (
    input  logic [127:0] key_in,   // current round key
    input  logic [3:0]   round,    // current round number (1–10)
    output logic [127:0] key_out   // next round key
);

    // ========================================================================
    // Extract the four 32-bit words from the current round key
    // FIPS 197 §5.2: key is treated as four 32-bit words w[0]..w[3]
    // ========================================================================
    logic [31:0] w0, w1, w2, w3;

    assign w0 = key_in[127:96];
    assign w1 = key_in[95:64];
    assign w2 = key_in[63:32];
    assign w3 = key_in[31:0];

    // ========================================================================
    // RotWord — FIPS 197 §5.2
    // Performs a cyclic LEFT rotation of the 4 bytes in w[3] by one byte:
    //   RotWord({b0, b1, b2, b3}) = {b1, b2, b3, b0}
    // ========================================================================
    logic [31:0] rot_word;

    assign rot_word = {w3[23:16], w3[15:8], w3[7:0], w3[31:24]};

    // ========================================================================
    // SubWord — FIPS 197 §5.2
    // Applies the AES S-Box substitution to each byte of RotWord output.
    // Four aes_sbox instances process the four bytes in parallel.
    // ========================================================================
    logic [7:0] sub_word [4];

    aes_sbox u_sbox_0 (
        .data_in  (rot_word[31:24]),
        .data_out (sub_word[0])
    );

    aes_sbox u_sbox_1 (
        .data_in  (rot_word[23:16]),
        .data_out (sub_word[1])
    );

    aes_sbox u_sbox_2 (
        .data_in  (rot_word[15:8]),
        .data_out (sub_word[2])
    );

    aes_sbox u_sbox_3 (
        .data_in  (rot_word[7:0]),
        .data_out (sub_word[3])
    );

    logic [31:0] sub_word_concat;
    assign sub_word_concat = {sub_word[0], sub_word[1], sub_word[2], sub_word[3]};

    // ========================================================================
    // Rcon — Round Constant (FIPS 197 §5.2, Table 5)
    // The round constant is XORed into only the most-significant byte of w[0].
    // Rcon[i] = {rc[i], 8'h00, 8'h00, 8'h00} where rc[i] is defined in GF(2^8).
    // ========================================================================
    logic [7:0] rcon;

    always_comb begin
        case (round)
            4'd1:    rcon = 8'h01;
            4'd2:    rcon = 8'h02;
            4'd3:    rcon = 8'h04;
            4'd4:    rcon = 8'h08;
            4'd5:    rcon = 8'h10;
            4'd6:    rcon = 8'h20;
            4'd7:    rcon = 8'h40;
            4'd8:    rcon = 8'h80;
            4'd9:    rcon = 8'h1b;  // x^8 mod m(x) = x^4 + x^3 + x + 1
            4'd10:   rcon = 8'h36;  // x^9 mod m(x)
            default: rcon = 8'h00;  // should not occur in AES-128
        endcase
    end

    // ========================================================================
    // Compute the next round key — FIPS 197 §5.2
    //
    //   new_w[0] = old_w[0] ^ SubWord(RotWord(old_w[3])) ^ Rcon[round]
    //   new_w[1] = old_w[1] ^ new_w[0]
    //   new_w[2] = old_w[2] ^ new_w[1]
    //   new_w[3] = old_w[3] ^ new_w[2]
    //
    // Note: Rcon is XORed only into the MSB byte of new_w[0].
    // ========================================================================
    logic [31:0] new_w0, new_w1, new_w2, new_w3;

    assign new_w0 = w0 ^ sub_word_concat ^ {rcon, 24'h000000};
    assign new_w1 = w1 ^ new_w0;
    assign new_w2 = w2 ^ new_w1;
    assign new_w3 = w3 ^ new_w2;

    // ========================================================================
    // Assemble the 128-bit output key from the four new words
    // ========================================================================
    assign key_out = {new_w0, new_w1, new_w2, new_w3};

endmodule
