//======================================================================
// aes_mixcolumns.sv
// AES MixColumns Transformation (NIST FIPS 197, Section 5.1.3)
//
// Pure combinational module that performs the MixColumns step of AES-128.
// Each column of the state is treated as a polynomial over GF(2^8) and
// multiplied modulo (x^4 + 1) by the fixed polynomial:
//   a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
//
// State byte ordering is COLUMN-MAJOR per FIPS 197 Section 3.4:
//   Byte 0  = state_in[127:120] = s[0][0]
//   Byte 1  = state_in[119:112] = s[1][0]
//   Byte 2  = state_in[111:104] = s[2][0]
//   Byte 3  = state_in[103:96]  = s[3][0]
//   Byte 4  = state_in[95:88]   = s[0][1]
//   ...
//   Byte 15 = state_in[7:0]     = s[3][3]
//
// Column j is composed of bytes [4j, 4j+1, 4j+2, 4j+3].
//======================================================================

module aes_mixcolumns (
    input  logic [127:0] state_in,
    output logic [127:0] state_out
);

    //------------------------------------------------------------------
    // xtime: Multiplication by {02} in GF(2^8)
    // FIPS 197 Section 4.2.1
    //
    // The reduction polynomial is m(x) = x^8 + x^4 + x^3 + x + 1,
    // represented as 0x11B. When the MSB is set before the left-shift,
    // we XOR with 0x1B to reduce back into the field.
    //------------------------------------------------------------------
    function automatic logic [7:0] xtime(input logic [7:0] a);
        xtime = {a[6:0], 1'b0} ^ (a[7] ? 8'h1b : 8'h00);
    endfunction

    //------------------------------------------------------------------
    // mix_column: Apply MixColumns to a single 4-byte column
    // FIPS 197 Section 5.1.3
    //
    // The matrix multiplication for one column [a0, a1, a2, a3]:
    //   | r0 |   | 02  03  01  01 |   | a0 |
    //   | r1 | = | 01  02  03  01 | * | a1 |
    //   | r2 |   | 01  01  02  03 |   | a2 |
    //   | r3 |   | 03  01  01  02 |   | a3 |
    //
    // Multiplication by {03} = xtime(a) ^ a  (i.e., {02}*a + {01}*a)
    // Multiplication by {02} = xtime(a)
    // Multiplication by {01} = a  (identity)
    //
    // Expanded:
    //   r0 = {02}*a0 ^ {03}*a1 ^ {01}*a2 ^ {01}*a3
    //      = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3
    //   r1 = {01}*a0 ^ {02}*a1 ^ {03}*a2 ^ {01}*a3
    //      = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3
    //   r2 = {01}*a0 ^ {01}*a1 ^ {02}*a2 ^ {03}*a3
    //      = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3
    //   r3 = {03}*a0 ^ {01}*a1 ^ {01}*a2 ^ {02}*a3
    //      = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3)
    //------------------------------------------------------------------
    function automatic logic [31:0] mix_column(input logic [31:0] col);
        logic [7:0] a0, a1, a2, a3;
        logic [7:0] r0, r1, r2, r3;

        a0 = col[31:24];
        a1 = col[23:16];
        a2 = col[15:8];
        a3 = col[7:0];

        r0 = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        r1 = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        r2 = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        r3 = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);

        mix_column = {r0, r1, r2, r3};
    endfunction

    //------------------------------------------------------------------
    // Apply MixColumns to all four columns of the state
    // Column 0: state_in[127:96]  (bytes 0-3)
    // Column 1: state_in[95:64]   (bytes 4-7)
    // Column 2: state_in[63:32]   (bytes 8-11)
    // Column 3: state_in[31:0]    (bytes 12-15)
    //------------------------------------------------------------------
    always_comb begin
        state_out[127:96] = mix_column(state_in[127:96]);   // Column 0
        state_out[95:64]  = mix_column(state_in[95:64]);    // Column 1
        state_out[63:32]  = mix_column(state_in[63:32]);    // Column 2
        state_out[31:0]   = mix_column(state_in[31:0]);     // Column 3
    end

endmodule
