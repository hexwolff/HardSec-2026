// ============================================================================
// nexys4ddr_top.sv — Nexys 4 DDR FPGA Top-Level Wrapper
//
// Integrates the AES-128 iterative core with a UART interface so a host PC
// can send plaintext + key and receive ciphertext over a USB-UART bridge.
//
// ── UART Protocol (115 200 baud, 8N1) ─────────────────────────────────────
//
//   Host → FPGA  (33 bytes):
//     Byte  0       : Command  (0x01 = Encrypt)
//     Bytes 1 – 16  : Plaintext (16 bytes, MSB first)
//     Bytes 17 – 32 : Key       (16 bytes, MSB first)
//
//   FPGA → Host  (17 bytes):
//     Byte  0       : Status   (0xA0 = OK, 0xE1 = unknown command)
//     Bytes 1 – 16  : Ciphertext (16 bytes, MSB first)
//
// ── Board I/O ─────────────────────────────────────────────────────────────
//   CLK100MHZ   : 100 MHz on-board oscillator
//   CPU_RESETN  : Active-low reset pushbutton
//   UART_TXD_IN : USB-UART RX (PC TX → FPGA RX)
//   UART_RXD_OUT: USB-UART TX (FPGA TX → PC RX)
//   LED[15:0]   : Status LEDs
// ============================================================================

module nexys4ddr_top (
    input  logic        CLK100MHZ,
    input  logic        CPU_RESETN,

    // USB-UART (active-high, directly from master XDC)
    input  logic        UART_TXD_IN,       // PC's TX → FPGA's RX
    output logic        UART_RXD_OUT,      // FPGA's TX → PC's RX

    // Status LEDs
    output logic [15:0] LED
);

    // ====================================================================
    // Parameters
    // ====================================================================
    localparam CLK_FREQ     = 100_000_000;
    localparam BAUD_RATE    = 115_200;
    localparam CLKS_PER_BIT = CLK_FREQ / BAUD_RATE;  // 868

    localparam CMD_ENCRYPT  = 8'h01;
    localparam STAT_OK      = 8'hA0;
    localparam STAT_ERR_CMD = 8'hE1;

    localparam RX_PACKET_LEN = 33;   // 1 cmd + 16 PT + 16 KEY
    localparam TX_PACKET_LEN = 17;   // 1 status + 16 CT

    // ====================================================================
    // Internal signals
    // ====================================================================
    logic        rst_n;
    assign rst_n = CPU_RESETN;

    // UART RX
    logic [7:0]  uart_rx_data;
    logic        uart_rx_valid;

    // UART TX
    logic [7:0]  uart_tx_data;
    logic        uart_tx_start;
    logic        uart_tx_busy;

    // AES core
    logic        aes_start;
    logic [127:0] aes_plaintext;
    logic [127:0] aes_key;
    logic [127:0] aes_ciphertext;
    logic        aes_busy;
    logic        aes_done;

    // ====================================================================
    // UART RX instance
    // ====================================================================
    uart_rx #(.CLKS_PER_BIT(CLKS_PER_BIT)) u_uart_rx (
        .clk        (CLK100MHZ),
        .rst_n      (rst_n),
        .rx_serial  (UART_TXD_IN),
        .rx_data    (uart_rx_data),
        .rx_valid   (uart_rx_valid)
    );

    // ====================================================================
    // UART TX instance
    // ====================================================================
    uart_tx #(.CLKS_PER_BIT(CLKS_PER_BIT)) u_uart_tx (
        .clk        (CLK100MHZ),
        .rst_n      (rst_n),
        .tx_data    (uart_tx_data),
        .tx_start   (uart_tx_start),
        .tx_serial  (UART_RXD_OUT),
        .tx_busy    (uart_tx_busy)
    );

    // ====================================================================
    // AES-128 core instance
    // ====================================================================
    aes128_core u_aes (
        .clk        (CLK100MHZ),
        .rst_n      (rst_n),
        .start      (aes_start),
        .plaintext  (aes_plaintext),
        .key        (aes_key),
        .ciphertext (aes_ciphertext),
        .busy       (aes_busy),
        .done       (aes_done)
    );

    // ====================================================================
    // Protocol Controller FSM
    // ====================================================================
    typedef enum logic [3:0] {
        FSM_IDLE,          // waiting for first byte (command)
        FSM_RX_DATA,       // receiving remaining 32 data bytes
        FSM_PARSE,         // parse command, start AES or return error
        FSM_WAIT_AES,      // waiting for AES done
        FSM_TX_RESP,       // transmitting response bytes
        FSM_TX_WAIT        // waiting for UART TX to finish current byte
    } fsm_state_t;

    fsm_state_t fsm_state;

    // Packet buffers
    logic [7:0]  rx_buf [0:RX_PACKET_LEN-1];   // 33-byte receive buffer
    logic [5:0]  rx_byte_cnt;                   // byte counter (0–32)

    logic [7:0]  tx_buf [0:TX_PACKET_LEN-1];   // 17-byte transmit buffer
    logic [4:0]  tx_byte_cnt;                   // byte counter (0–16)

    // Encryption counter for LED display
    logic [15:0] encrypt_count;

    always_ff @(posedge CLK100MHZ) begin
        if (!rst_n) begin
            fsm_state     <= FSM_IDLE;
            rx_byte_cnt   <= '0;
            tx_byte_cnt   <= '0;
            aes_start     <= 1'b0;
            aes_plaintext <= '0;
            aes_key       <= '0;
            uart_tx_data  <= '0;
            uart_tx_start <= 1'b0;
            encrypt_count <= '0;
        end else begin
            // Defaults
            aes_start     <= 1'b0;
            uart_tx_start <= 1'b0;

            case (fsm_state)

                // ────────────────────────────────────────────────────────
                // IDLE: Wait for the command byte
                // ────────────────────────────────────────────────────────
                FSM_IDLE: begin
                    rx_byte_cnt <= '0;
                    tx_byte_cnt <= '0;
                    if (uart_rx_valid) begin
                        rx_buf[0]   <= uart_rx_data;
                        rx_byte_cnt <= 6'd1;
                        fsm_state   <= FSM_RX_DATA;
                    end
                end

                // ────────────────────────────────────────────────────────
                // RX_DATA: Collect the remaining 32 bytes (PT + Key)
                // ────────────────────────────────────────────────────────
                FSM_RX_DATA: begin
                    if (uart_rx_valid) begin
                        rx_buf[rx_byte_cnt] <= uart_rx_data;
                        if (rx_byte_cnt == RX_PACKET_LEN - 1) begin
                            fsm_state <= FSM_PARSE;
                        end else begin
                            rx_byte_cnt <= rx_byte_cnt + 1;
                        end
                    end
                end

                // ────────────────────────────────────────────────────────
                // PARSE: Extract PT & Key, launch AES or report error
                // ────────────────────────────────────────────────────────
                FSM_PARSE: begin
                    if (rx_buf[0] == CMD_ENCRYPT) begin
                        // Bytes 1–16 → plaintext (MSB first)
                        aes_plaintext <= {
                            rx_buf[1],  rx_buf[2],  rx_buf[3],  rx_buf[4],
                            rx_buf[5],  rx_buf[6],  rx_buf[7],  rx_buf[8],
                            rx_buf[9],  rx_buf[10], rx_buf[11], rx_buf[12],
                            rx_buf[13], rx_buf[14], rx_buf[15], rx_buf[16]
                        };
                        // Bytes 17–32 → key (MSB first)
                        aes_key <= {
                            rx_buf[17], rx_buf[18], rx_buf[19], rx_buf[20],
                            rx_buf[21], rx_buf[22], rx_buf[23], rx_buf[24],
                            rx_buf[25], rx_buf[26], rx_buf[27], rx_buf[28],
                            rx_buf[29], rx_buf[30], rx_buf[31], rx_buf[32]
                        };
                        aes_start <= 1'b1;
                        fsm_state <= FSM_WAIT_AES;
                    end else begin
                        // Unknown command → send error response (all-zero CT)
                        tx_buf[0] <= STAT_ERR_CMD;
                        for (int j = 1; j < TX_PACKET_LEN; j++)
                            tx_buf[j] <= 8'h00;
                        tx_byte_cnt <= '0;
                        fsm_state   <= FSM_TX_RESP;
                    end
                end

                // ────────────────────────────────────────────────────────
                // WAIT_AES: Wait for AES core done pulse
                // ────────────────────────────────────────────────────────
                FSM_WAIT_AES: begin
                    if (aes_done) begin
                        // Pack response: status + 16 ciphertext bytes
                        tx_buf[0]  <= STAT_OK;
                        tx_buf[1]  <= aes_ciphertext[127:120];
                        tx_buf[2]  <= aes_ciphertext[119:112];
                        tx_buf[3]  <= aes_ciphertext[111:104];
                        tx_buf[4]  <= aes_ciphertext[103:96];
                        tx_buf[5]  <= aes_ciphertext[95:88];
                        tx_buf[6]  <= aes_ciphertext[87:80];
                        tx_buf[7]  <= aes_ciphertext[79:72];
                        tx_buf[8]  <= aes_ciphertext[71:64];
                        tx_buf[9]  <= aes_ciphertext[63:56];
                        tx_buf[10] <= aes_ciphertext[55:48];
                        tx_buf[11] <= aes_ciphertext[47:40];
                        tx_buf[12] <= aes_ciphertext[39:32];
                        tx_buf[13] <= aes_ciphertext[31:24];
                        tx_buf[14] <= aes_ciphertext[23:16];
                        tx_buf[15] <= aes_ciphertext[15:8];
                        tx_buf[16] <= aes_ciphertext[7:0];
                        tx_byte_cnt   <= '0;
                        encrypt_count <= encrypt_count + 1;
                        fsm_state     <= FSM_TX_RESP;
                    end
                end

                // ────────────────────────────────────────────────────────
                // TX_RESP: Send the next byte if TX is free
                // ────────────────────────────────────────────────────────
                FSM_TX_RESP: begin
                    if (!uart_tx_busy) begin
                        uart_tx_data  <= tx_buf[tx_byte_cnt];
                        uart_tx_start <= 1'b1;
                        fsm_state     <= FSM_TX_WAIT;
                    end
                end

                // ────────────────────────────────────────────────────────
                // TX_WAIT: Wait for byte to finish, then next or done
                // ────────────────────────────────────────────────────────
                FSM_TX_WAIT: begin
                    // uart_tx_start was pulsed in TX_RESP, TX is now busy
                    if (!uart_tx_busy) begin
                        if (tx_byte_cnt == TX_PACKET_LEN - 1) begin
                            fsm_state <= FSM_IDLE;    // all bytes sent
                        end else begin
                            tx_byte_cnt <= tx_byte_cnt + 1;
                            fsm_state   <= FSM_TX_RESP;
                        end
                    end
                end

                default: fsm_state <= FSM_IDLE;
            endcase
        end
    end

    // ====================================================================
    // LED Indicators
    // ====================================================================
    //   LED[15]   : AES busy
    //   LED[14]   : UART TX busy
    //   LED[13:0] : lower 14 bits of encryption counter
    assign LED[15]   = aes_busy;
    assign LED[14]   = uart_tx_busy;
    assign LED[13:0] = encrypt_count[13:0];

endmodule
