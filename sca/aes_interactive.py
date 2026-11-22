#!/usr/bin/env python3
"""
aes_interactive.py — Interactive AES-128 FPGA Console
HardSec 2026

Type plaintext and key as hex strings, see the ciphertext come back
from the Nexys 4 DDR FPGA in real time. No RTL changes needed — this
script wraps the existing binary UART protocol.

Usage:
    source .venv/bin/activate
    python3 sca/aes_interactive.py --port /dev/ttyUSB1
"""

import argparse
import sys
import time

try:
    import serial
except ImportError:
    print("Run:  pip install pyserial")
    sys.exit(1)

# ── Protocol constants (must match nexys4ddr_top.sv) ────────────────────
CMD_ENCRYPT  = 0x01
STAT_OK      = 0xA0

BANNER = r"""
 ╔══════════════════════════════════════════════════════════════╗
 ║          AES-128 FPGA Interactive Console                   ║
 ║          Nexys 4 DDR  ·  115200 baud  ·  8N1                ║
 ╠══════════════════════════════════════════════════════════════╣
 ║  Type 32-hex-char plaintext and 32-hex-char key.            ║
 ║  The FPGA encrypts and returns the ciphertext.              ║
 ║                                                             ║
 ║  Commands:                                                  ║
 ║    Just enter PT and KEY when prompted                      ║
 ║    'q' or 'quit' or Ctrl+C to exit                          ║
 ╚══════════════════════════════════════════════════════════════╝
"""


def parse_hex(prompt: str, expected_len: int) -> bytes | None:
    """Read a hex string from stdin, return bytes or None on quit."""
    while True:
        try:
            raw = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None

        if raw in ("q", "quit", "exit"):
            return None

        # Strip optional "0x" prefix and spaces
        raw = raw.replace("0x", "").replace(" ", "")

        if len(raw) != expected_len * 2:
            print(f"  ✗ Need exactly {expected_len * 2} hex characters "
                  f"({expected_len} bytes), got {len(raw)}. Try again.")
            continue

        try:
            return bytes.fromhex(raw)
        except ValueError:
            print("  ✗ Invalid hex characters. Use 0-9 and a-f only.")


def send_encrypt(ser: serial.Serial, pt: bytes, key: bytes) -> tuple[int, bytes]:
    """Send encrypt packet, return (status, ciphertext)."""
    packet = bytes([CMD_ENCRYPT]) + pt + key
    ser.reset_input_buffer()          # flush any stale data
    ser.write(packet)
    resp = ser.read(17)
    if len(resp) != 17:
        raise TimeoutError(f"Timeout — got {len(resp)}/17 bytes back")
    return resp[0], resp[1:17]


def main():
    parser = argparse.ArgumentParser(description="Interactive AES-128 FPGA console")
    parser.add_argument("--port", type=str, default="/dev/ttyUSB1")
    parser.add_argument("--baud", type=int, default=115200)
    args = parser.parse_args()

    print(BANNER)
    print(f"  Opening {args.port} @ {args.baud} baud … ", end="", flush=True)

    try:
        ser = serial.Serial(args.port, args.baud, timeout=3)
    except serial.SerialException as e:
        print(f"\n  ✗ {e}")
        sys.exit(1)

    ser.reset_input_buffer()
    ser.reset_output_buffer()
    time.sleep(0.1)
    print("OK ✓\n")

    count = 0
    while True:
        print(f"  ── Encryption #{count + 1} ──")

        pt = parse_hex("  Plaintext  (32 hex chars): ", 16)
        if pt is None:
            break

        key = parse_hex("  Key        (32 hex chars): ", 16)
        if key is None:
            break

        try:
            status, ct = send_encrypt(ser, pt, key)
        except TimeoutError as e:
            print(f"  ✗ {e}")
            continue

        print()
        if status == STAT_OK:
            print(f"  ┌─ Plaintext:  {pt.hex()}")
            print(f"  │  Key:        {key.hex()}")
            print(f"  └─ Ciphertext: {ct.hex()}  ✓")
        else:
            print(f"  ✗ FPGA returned error status: 0x{status:02x}")

        count += 1
        print()

    ser.close()
    print(f"\n  Bye! ({count} encryption(s) performed)")


if __name__ == "__main__":
    main()
