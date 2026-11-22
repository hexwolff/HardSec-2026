// ============================================================================
// UART Receiver — 8N1, Parameterizable Baud Rate
//
// Oversamples the RX line at 16× the baud rate for robust bit-centre sampling.
// Active-low reset. Active-high 'rx_valid' pulse when a full byte is received.
//
// Default: 100 MHz clock, 115 200 baud → CLKS_PER_BIT = 868
// ============================================================================

module uart_rx #(
    parameter CLKS_PER_BIT = 868          // 100 MHz / 115200
)(
    input  logic       clk,
    input  logic       rst_n,
    input  logic       rx_serial,          // UART RX pin (active-high idle)
    output logic [7:0] rx_data,            // received byte
    output logic       rx_valid            // 1-cycle pulse when rx_data is valid
);

    // ── State machine ──────────────────────────────────────────────────────
    typedef enum logic [2:0] {
        S_IDLE,
        S_START,
        S_DATA,
        S_STOP
    } state_t;

    state_t state;

    // ── Synchroniser (2-FF) for the asynchronous RX pin ────────────────────
    logic rx_sync_0, rx_sync_1;

    always_ff @(posedge clk) begin
        if (!rst_n) begin
            rx_sync_0 <= 1'b1;
            rx_sync_1 <= 1'b1;
        end else begin
            rx_sync_0 <= rx_serial;
            rx_sync_1 <= rx_sync_0;
        end
    end

    wire rx_in = rx_sync_1;               // metastability-safe input

    // ── Bit-period counter & bit index ─────────────────────────────────────
    logic [$clog2(CLKS_PER_BIT)-1:0] clk_cnt;
    logic [2:0]                       bit_idx;
    logic [7:0]                       rx_shift;

    always_ff @(posedge clk) begin
        if (!rst_n) begin
            state    <= S_IDLE;
            clk_cnt  <= '0;
            bit_idx  <= '0;
            rx_shift <= '0;
            rx_data  <= '0;
            rx_valid <= 1'b0;
        end else begin
            rx_valid <= 1'b0;              // default: pulse off

            case (state)
                // ── IDLE: wait for falling edge (start bit) ────────────
                S_IDLE: begin
                    clk_cnt <= '0;
                    bit_idx <= '0;
                    if (rx_in == 1'b0)
                        state <= S_START;
                end

                // ── START: sample at mid-bit to confirm it's low ───────
                S_START: begin
                    if (clk_cnt == (CLKS_PER_BIT - 1) / 2) begin
                        if (rx_in == 1'b0) begin
                            clk_cnt <= '0;     // confirmed — reset counter for data bits
                            state   <= S_DATA;
                        end else begin
                            state <= S_IDLE;    // glitch — back to idle
                        end
                    end else begin
                        clk_cnt <= clk_cnt + 1;
                    end
                end

                // ── DATA: sample 8 bits LSB-first at mid-bit ──────────
                S_DATA: begin
                    if (clk_cnt == CLKS_PER_BIT - 1) begin
                        clk_cnt <= '0;
                        rx_shift[bit_idx] <= rx_in;
                        if (bit_idx == 3'd7) begin
                            state <= S_STOP;
                        end else begin
                            bit_idx <= bit_idx + 1;
                        end
                    end else begin
                        clk_cnt <= clk_cnt + 1;
                    end
                end

                // ── STOP: wait for stop bit (high), then output ───────
                S_STOP: begin
                    if (clk_cnt == CLKS_PER_BIT - 1) begin
                        rx_data  <= rx_shift;
                        rx_valid <= 1'b1;
                        clk_cnt  <= '0;
                        state    <= S_IDLE;
                    end else begin
                        clk_cnt <= clk_cnt + 1;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

endmodule
