// ============================================================================
// PRNG (Pseudo-Random Number Generator) — 128-bit Galois LFSR
//
// Generates 128-bit random masks for the first-order Boolean masking
// countermeasure in the masked AES-128 core.
//
// Polynomial: x^128 + x^7 + x^2 + x + 1 (primitive over GF(2))
// — This is a maximal-length LFSR with period 2^128 - 1.
//
// Operation:
//   - On rst_n deassertion, loads seed_in as the initial state.
//   - When advance=1, shifts the LFSR by 128 positions in one cycle
//     (fully unrolled feedback) to produce a fresh 128-bit random value.
//   - rng_out always reflects the current LFSR state.
//
// Reference: Xilinx XAPP052 "Efficient Shift Registers, LFSR Counters,
//            and Long Pseudo-Random Sequence Generators"
// ============================================================================

module prng_lfsr (
    input  logic         clk,
    input  logic         rst_n,
    input  logic [127:0] seed_in,   // non-zero seed loaded on reset
    input  logic         advance,   // pulse to generate next 128-bit value
    output logic [127:0] rng_out    // current random output
);

    logic [127:0] lfsr_reg;

    // ========================================================================
    // Galois LFSR step function (single-bit shift)
    // Polynomial: x^128 + x^7 + x^2 + x + 1
    // Feedback taps at positions 128, 7, 2, 1 (1-indexed)
    // ========================================================================
    function automatic logic [127:0] lfsr_step(input logic [127:0] state);
        logic feedback;
        logic [127:0] next;
        feedback = state[127];  // MSB is the feedback bit
        next = {state[126:0], 1'b0};  // shift left by 1
        // XOR feedback into tap positions (positions 7, 2, 1, 0 in 0-indexed)
        next[0] = next[0] ^ feedback;
        next[1] = next[1] ^ feedback;
        next[2] = next[2] ^ feedback;
        next[7] = next[7] ^ feedback;
        return next;
    endfunction

    // ========================================================================
    // Advance LFSR by 128 bits in one clock cycle (unrolled)
    // This is equivalent to 128 single-bit shifts, producing a fully
    // refreshed 128-bit output with no correlation to the previous value.
    // ========================================================================
    function automatic logic [127:0] lfsr_advance_128(input logic [127:0] state);
        logic [127:0] s;
        s = state;
        // Unroll 128 single-bit steps
        for (int i = 0; i < 128; i++) begin
            s = lfsr_step(s);
        end
        return s;
    endfunction

    // ========================================================================
    // Sequential logic
    // ========================================================================
    always_ff @(posedge clk) begin
        if (!rst_n) begin
            lfsr_reg <= seed_in;
        end else if (advance) begin
            lfsr_reg <= lfsr_advance_128(lfsr_reg);
        end
    end

    assign rng_out = lfsr_reg;

endmodule
