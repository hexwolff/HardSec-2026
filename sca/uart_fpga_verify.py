#!/usr/bin/env python3
"""
uart_fpga_verify.py — AES-128 FPGA Hardware Verification over UART
HardSec 2026

Sends NIST FIPS 197 test vectors and random plaintext/key pairs to the
Nexys 4 DDR FPGA over the USB-UART bridge, receives ciphertext, and
validates against a Python golden reference.

Protocol (115 200 baud, 8N1):
    Host → FPGA  (33 bytes):  [0x01] [PT: 16 bytes] [KEY: 16 bytes]
    FPGA → Host  (17 bytes):  [status] [CT: 16 bytes]

Usage:
    python3 uart_fpga_verify.py                      # auto-detect port
    python3 uart_fpga_verify.py --port /dev/ttyUSB1  # explicit port
    python3 uart_fpga_verify.py --count 500          # number of random tests
    python3 uart_fpga_verify.py --baud 115200        # explicit baud rate
"""

import argparse
import os
import sys
import time
import struct
from typing import Optional, Tuple

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    print("ERROR: pyserial not installed. Run:  pip install pyserial")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("ERROR: cryptography not installed. Run:  pip install cryptography")
    sys.exit(1)


# ── Protocol constants ──────────────────────────────────────────────────────
CMD_ENCRYPT  = 0x01
STAT_OK      = 0xA0
STAT_ERR_CMD = 0xE1

TX_PACKET_LEN = 33   # 1 cmd + 16 PT + 16 KEY
RX_PACKET_LEN = 17   # 1 status + 16 CT


# ── AES golden reference ───────────────────────────────────────────────────
def aes128_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt a single 16-byte block with AES-128-ECB."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()


# ── Serial helpers ──────────────────────────────────────────────────────────
def auto_detect_port() -> Optional[str]:
    """Find the first likely Nexys 4 DDR USB-UART port."""
    for p in serial.tools.list_ports.comports():
        desc = (p.description or "").lower()
        vid_pid = f"{p.vid:04x}:{p.pid:04x}" if p.vid and p.pid else ""
        # Digilent boards use FTDI FT2232HQ (VID 0403:6010)
        if "0403:6010" in vid_pid or "digilent" in desc or "ft2232" in desc:
            return p.device
        # Fallback: any ttyUSB or ttyACM
        if "ttyUSB" in p.device or "ttyACM" in p.device:
            return p.device
    return None


def send_encrypt(ser: serial.Serial, plaintext: bytes, key: bytes) -> Tuple[int, bytes]:
    """
    Send an encrypt command over UART and receive the response.
    Returns (status_byte, ciphertext_bytes).
    """
    assert len(plaintext) == 16 and len(key) == 16

    # Build and send packet
    packet = bytes([CMD_ENCRYPT]) + plaintext + key
    assert len(packet) == TX_PACKET_LEN
    ser.write(packet)

    # Read response (with timeout)
    resp = ser.read(RX_PACKET_LEN)
    if len(resp) != RX_PACKET_LEN:
        raise TimeoutError(
            f"Expected {RX_PACKET_LEN} bytes, got {len(resp)}. "
            f"Check FPGA is programmed and UART cable is connected."
        )

    status = resp[0]
    ct     = resp[1:17]
    return status, ct


# ── NIST FIPS 197 test vectors ─────────────────────────────────────────────
NIST_VECTORS = [
    {
        "name": "FIPS 197 Appendix B",
        "pt":   bytes.fromhex("3243f6a8885a308d313198a2e0370734"),
        "key":  bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        "ct":   bytes.fromhex("3925841d02dc09fbdc118597196a0b32"),
    },
    {
        "name": "FIPS 197 Appendix C.1",
        "pt":   bytes.fromhex("00112233445566778899aabbccddeeff"),
        "key":  bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        "ct":   bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
    },
    {
        "name": "All-Zeros",
        "pt":   bytes(16),
        "key":  bytes(16),
        "ct":   bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e"),
    },
]


# ── Main ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="AES-128 FPGA verification over UART (Nexys 4 DDR)"
    )
    parser.add_argument("--port",  type=str, default=None,
                        help="Serial port (e.g. /dev/ttyUSB1). Auto-detected if omitted.")
    parser.add_argument("--baud",  type=int, default=115200,
                        help="Baud rate (default: 115200)")
    parser.add_argument("--count", type=int, default=100,
                        help="Number of random test vectors (default: 100)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="Per-packet read timeout in seconds (default: 2.0)")
    args = parser.parse_args()

    # ── Open serial port ────────────────────────────────────────────────
    port = args.port or auto_detect_port()
    if port is None:
        print("ERROR: No serial port found. Connect the FPGA and retry,")
        print("       or specify --port /dev/ttyUSBx explicitly.")
        sys.exit(1)

    print(f"Opening {port} @ {args.baud} baud …")
    ser = serial.Serial(
        port=port,
        baudrate=args.baud,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=args.timeout,
    )
    # Flush any stale data
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    time.sleep(0.1)

    pass_count = 0
    fail_count = 0
    total      = 0

    print("=" * 70)
    print("AES-128 FPGA Hardware Verification")
    print("=" * 70)

    # ── NIST test vectors ───────────────────────────────────────────────
    print("\n── NIST FIPS 197 Test Vectors ──")
    for vec in NIST_VECTORS:
        try:
            status, ct_hw = send_encrypt(ser, vec["pt"], vec["key"])
        except TimeoutError as e:
            print(f"  FAIL [{vec['name']}]: {e}")
            fail_count += 1
            total += 1
            continue

        total += 1
        if status != STAT_OK:
            print(f"  FAIL [{vec['name']}]: bad status 0x{status:02x}")
            fail_count += 1
        elif ct_hw != vec["ct"]:
            print(f"  FAIL [{vec['name']}]:")
            print(f"    Expected: {vec['ct'].hex()}")
            print(f"    Got:      {ct_hw.hex()}")
            fail_count += 1
        else:
            print(f"  PASS [{vec['name']}]  CT = {ct_hw.hex()}")
            pass_count += 1

    # ── Random test vectors ─────────────────────────────────────────────
    print(f"\n── Random Vectors ({args.count}) ──")
    for i in range(args.count):
        pt  = os.urandom(16)
        key = os.urandom(16)
        ct_ref = aes128_encrypt(pt, key)

        try:
            status, ct_hw = send_encrypt(ser, pt, key)
        except TimeoutError as e:
            print(f"  FAIL [Random #{i}]: {e}")
            fail_count += 1
            total += 1
            continue

        total += 1
        if status != STAT_OK or ct_hw != ct_ref:
            print(f"  FAIL [Random #{i}]:")
            print(f"    PT:       {pt.hex()}")
            print(f"    KEY:      {key.hex()}")
            print(f"    Expected: {ct_ref.hex()}")
            print(f"    Got:      {ct_hw.hex()}  (status=0x{status:02x})")
            fail_count += 1
        else:
            pass_count += 1

        # Progress every 10 vectors
        if (i + 1) % 10 == 0:
            print(f"  … {i + 1}/{args.count} done", end="\r")

    print(f"  … {args.count}/{args.count} done    ")

    # ── Summary ─────────────────────────────────────────────────────────
    ser.close()

    print("\n" + "=" * 70)
    print(f"RESULTS: {pass_count} / {total} passed  ({fail_count} failed)")
    if fail_count == 0:
        print(">>> ALL TESTS PASSED <<<")
    else:
        print(">>> SOME TESTS FAILED <<<")
    print("=" * 70)
    sys.exit(0 if fail_count == 0 else 1)


if __name__ == "__main__":
    main()
