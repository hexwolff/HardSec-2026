// ============================================================================
// AES-128 Encryption Core — Iterative, 11-Cycle, Encryption-Only
// Per NIST FIPS 197
//
// Architecture:
//   - Cycle 0:  Initial AddRoundKey (plaintext ^ key_0), latch into state_reg
//   - Cycles 1–9: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
//   - Cycle 10: Final round (SubBytes -> ShiftRows -> AddRoundKey, no MixColumns)
//   - On-the-fly key expansion: round key computed in parallel each cycle
//
// Interface:
//   clk         — system clock (rising edge)
//   rst_n       — active-low synchronous reset
//   start       — pulse high for 1 cycle to begin encryption
//   plaintext   — 128-bit input plaintext (latched on start)
//   key         — 128-bit cipher key (latched on start)
//   ciphertext  — 128-bit output (valid when done=1)
//   busy        — high while encryption is in progress
//   done        — pulsed high for 1 cycle when ciphertext is ready
// ============================================================================

module aes128_core (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         start,
    input  logic [127:0] plaintext,
    input  logic [127:0] key,
    output logic [127:0] ciphertext,
    output logic         busy,
    output logic         done
);

    // ========================================================================
    // Internal registers
    // ========================================================================
    logic [127:0] state_reg;      // 128-bit AES state
    logic [127:0] key_reg;        // 128-bit current round key
    logic [3:0]   round_cnt;      // round counter (0–10)
    logic         running;        // FSM: encryption in progress

    // ========================================================================
    // SubBytes: 16 parallel S-box instances for the state
    // FIPS 197 §5.1.1 — byte-wise substitution
    // ========================================================================
    logic [127:0] after_subbytes;

    genvar i;
    generate
        for (i = 0; i < 16; i++) begin : gen_subbytes
            aes_sbox u_sbox (
                .data_in  (state_reg[127 - 8*i -: 8]),
                .data_out (after_subbytes[127 - 8*i -: 8])
            );
        end
    endgenerate

    // ========================================================================
    // ShiftRows: cyclic left-shift of each row
    // FIPS 197 §5.1.2
    //
    // State layout (column-major, MSB-first):
    //   Byte index:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    //   Row/Col:   [0,0][1,0][2,0][3,0] [0,1][1,1][2,1][3,1] ...
    //
    //   Row 0 (bytes 0,4,8,12):   no shift
    //   Row 1 (bytes 1,5,9,13):   shift left by 1
    //   Row 2 (bytes 2,6,10,14):  shift left by 2
    //   Row 3 (bytes 3,7,11,15):  shift left by 3
    // ========================================================================
    logic [127:0] after_shiftrows;

    // Extract individual bytes from after_subbytes for clarity
    // Byte n is at bits [127-8*n -: 8]
    // Using wire assignments for the 16-byte permutation:
    always_comb begin
        // Row 0: no shift — bytes 0, 4, 8, 12 stay in place
        after_shiftrows[127:120] = after_subbytes[127:120]; // byte 0  -> pos 0
        after_shiftrows[95:88]   = after_subbytes[95:88];   // byte 4  -> pos 4
        after_shiftrows[63:56]   = after_subbytes[63:56];   // byte 8  -> pos 8
        after_shiftrows[31:24]   = after_subbytes[31:24];   // byte 12 -> pos 12

        // Row 1: shift left by 1 — bytes 1,5,9,13 rotate positions
        // Original: col0=byte1, col1=byte5, col2=byte9, col3=byte13
        // After:    col0=byte5, col1=byte9, col2=byte13, col3=byte1
        after_shiftrows[119:112] = after_subbytes[87:80];   // byte 5  -> pos 1
        after_shiftrows[87:80]   = after_subbytes[55:48];   // byte 9  -> pos 5
        after_shiftrows[55:48]   = after_subbytes[23:16];   // byte 13 -> pos 9
        after_shiftrows[23:16]   = after_subbytes[119:112]; // byte 1  -> pos 13

        // Row 2: shift left by 2 — bytes 2,6,10,14 rotate positions
        // Original: col0=byte2, col1=byte6, col2=byte10, col3=byte14
        // After:    col0=byte10, col1=byte14, col2=byte2, col3=byte6
        after_shiftrows[111:104] = after_subbytes[47:40];   // byte 10 -> pos 2
        after_shiftrows[79:72]   = after_subbytes[15:8];    // byte 14 -> pos 6
        after_shiftrows[47:40]   = after_subbytes[111:104]; // byte 2  -> pos 10
        after_shiftrows[15:8]    = after_subbytes[79:72];   // byte 6  -> pos 14

        // Row 3: shift left by 3 (= right by 1) — bytes 3,7,11,15 rotate positions
        // Original: col0=byte3, col1=byte7, col2=byte11, col3=byte15
        // After:    col0=byte15, col1=byte3, col2=byte7, col3=byte11
        after_shiftrows[103:96]  = after_subbytes[7:0];     // byte 15 -> pos 3
        after_shiftrows[71:64]   = after_subbytes[103:96];  // byte 3  -> pos 7
        after_shiftrows[39:32]   = after_subbytes[71:64];   // byte 7  -> pos 11
        after_shiftrows[7:0]     = after_subbytes[39:32];   // byte 11 -> pos 15
    end

    // ========================================================================
    // MixColumns: GF(2^8) column mixing
    // FIPS 197 §5.1.3 — applied in rounds 1–9 only (skipped in round 10)
    // ========================================================================
    logic [127:0] after_mixcolumns;

    aes_mixcolumns u_mixcol (
        .state_in  (after_shiftrows),
        .state_out (after_mixcolumns)
    );

    // ========================================================================
    // On-the-fly Key Expansion
    // FIPS 197 §5.2 — computes next round key from current key_reg
    // ========================================================================
    logic [127:0] next_round_key;

    aes_key_expand u_key_expand (
        .key_in  (key_reg),
        .round   (round_cnt),
        .key_out (next_round_key)
    );

    // ========================================================================
    // AddRoundKey: XOR state with round key
    // FIPS 197 §5.1.4
    // ========================================================================
    // For rounds 1-9: after MixColumns XOR with next round key
    // For round 10:   after ShiftRows XOR with next round key (no MixColumns)
    logic [127:0] after_addroundkey;

    always_comb begin
        if (round_cnt == 4'd10)
            after_addroundkey = after_shiftrows ^ next_round_key;
        else
            after_addroundkey = after_mixcolumns ^ next_round_key;
    end

    // ========================================================================
    // FSM & Datapath Control
    // ========================================================================
    always_ff @(posedge clk) begin
        if (!rst_n) begin
            state_reg  <= 128'b0;
            key_reg    <= 128'b0;
            round_cnt  <= 4'd0;
            running    <= 1'b0;
            done       <= 1'b0;
            ciphertext <= 128'b0;
        end else begin
            done <= 1'b0;  // default: done is a 1-cycle pulse

            if (start && !running) begin
                // Cycle 0: Initial AddRoundKey (plaintext ^ key_0)
                state_reg <= plaintext ^ key;
                key_reg   <= key;
                round_cnt <= 4'd1;
                running   <= 1'b1;
            end else if (running) begin
                if (round_cnt == 4'd10) begin
                    // Final round complete
                    ciphertext <= after_addroundkey;
                    done       <= 1'b1;
                    running    <= 1'b0;
                    round_cnt  <= 4'd0;
                end else begin
                    // Rounds 1–9: advance state and key
                    state_reg <= after_addroundkey;
                    key_reg   <= next_round_key;
                    round_cnt <= round_cnt + 4'd1;
                end
            end
        end
    end

    // ========================================================================
    // Busy signal
    // ========================================================================
    assign busy = running;

endmodule
