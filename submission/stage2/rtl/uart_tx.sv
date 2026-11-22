// ============================================================================
// UART Transmitter — 8N1, Parameterizable Baud Rate
//
// Sends one byte at a time (start + 8 data LSB-first + stop).
// Assert 'tx_start' for 1 cycle with 'tx_data' valid; 'tx_busy' stays high
// until the full frame (10 bits) has been transmitted.
//
// Default: 100 MHz clock, 115 200 baud → CLKS_PER_BIT = 868
// ============================================================================

module uart_tx #(
    parameter CLKS_PER_BIT = 868          // 100 MHz / 115200
)(
    input  logic       clk,
    input  logic       rst_n,
    input  logic [7:0] tx_data,            // byte to send
    input  logic       tx_start,           // 1-cycle pulse to begin TX
    output logic       tx_serial,          // UART TX pin
    output logic       tx_busy             // high while transmitting
);

    // ── State machine ──────────────────────────────────────────────────────
    typedef enum logic [2:0] {
        S_IDLE,
        S_START,
        S_DATA,
        S_STOP
    } state_t;

    state_t state;

    logic [$clog2(CLKS_PER_BIT)-1:0] clk_cnt;
    logic [2:0]                       bit_idx;
    logic [7:0]                       tx_shift;

    always_ff @(posedge clk) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            clk_cnt   <= '0;
            bit_idx   <= '0;
            tx_shift  <= '0;
            tx_serial <= 1'b1;             // idle-high
            tx_busy   <= 1'b0;
        end else begin
            case (state)
                // ── IDLE: wait for tx_start ────────────────────────────
                S_IDLE: begin
                    tx_serial <= 1'b1;
                    tx_busy   <= 1'b0;
                    clk_cnt   <= '0;
                    bit_idx   <= '0;
                    if (tx_start) begin
                        tx_shift <= tx_data;
                        tx_busy  <= 1'b1;
                        state    <= S_START;
                    end
                end

                // ── START bit (low) ───────────────────────────────────
                S_START: begin
                    tx_serial <= 1'b0;
                    if (clk_cnt == CLKS_PER_BIT - 1) begin
                        clk_cnt <= '0;
                        state   <= S_DATA;
                    end else begin
                        clk_cnt <= clk_cnt + 1;
                    end
                end

                // ── DATA: 8 bits LSB-first ────────────────────────────
                S_DATA: begin
                    tx_serial <= tx_shift[bit_idx];
                    if (clk_cnt == CLKS_PER_BIT - 1) begin
                        clk_cnt <= '0;
                        if (bit_idx == 3'd7) begin
                            state <= S_STOP;
                        end else begin
                            bit_idx <= bit_idx + 1;
                        end
                    end else begin
                        clk_cnt <= clk_cnt + 1;
                    end
                end

                // ── STOP bit (high) ───────────────────────────────────
                S_STOP: begin
                    tx_serial <= 1'b1;
                    if (clk_cnt == CLKS_PER_BIT - 1) begin
                        clk_cnt <= '0;
                        tx_busy <= 1'b0;
                        state   <= S_IDLE;
                    end else begin
                        clk_cnt <= clk_cnt + 1;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
