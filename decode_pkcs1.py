#!/usr/bin/env python3
import sys
import argparse

def parse_int(s: str) -> int:
    s = s.strip()
    try:
        if s.startswith("0x") or any(c in s.lower() for c in "abcdef"):
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        raise SystemExit("Input must be a decimal integer or hex starting with 0x")

def to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

def safe_ascii(b: bytes) -> str:
    try:
        return b.decode("utf-8")
    except Exception:
        return b.decode("latin1", "replace")

def main():
    p = argparse.ArgumentParser(description="Decode a PKCS#1 v1.5 padded plaintext integer.")
    p.add_argument("value", nargs="?", help="Recovered integer value (decimal or 0x-hex). Use '-' to read from stdin.")
    p.add_argument("--mod-bytes", type=int, default=None, help="Modulus size in bytes to left-pad the value (e.g., 128 for 1024-bit).")
    p.add_argument("--trailing-len", type=int, default=32, help="How many trailing bytes to display in hex/ascii.")
    p.add_argument("--find", default=None, help="Optional ASCII substring to search for (e.g., 'lol').")
    args = p.parse_args()

    if not args.value or args.value == "-":
        data = sys.stdin.read()
        if not data:
            raise SystemExit("No input provided on stdin.")
        n = parse_int(data)
    else:
        n = parse_int(args.value)

    b = to_bytes(n)
    if args.mod_bytes and len(b) < args.mod_bytes:
        b = b.rjust(args.mod_bytes, b"\x00")

    print("total_bytes:", len(b))
    print("starts_with_0x02:", len(b) > 0 and b[0] == 0x02)

    # PKCS#1 v1.5 structure (for encryption): 0x00 0x02 | PS (non-zero) | 0x00 | M
    # Some demos omit the initial 0x00; this script is tolerant.
    # Try to find the first 0x00 following any initial 0x02 prefix and treat the rest as message.
    try:
        # If first byte is 0x00, look for delimiter after 0x02 region; else search globally.
        start = 2 if len(b) > 1 and b[0] in (0x00, 0x02) else 0
        zero_idx = b.index(0x00, start)
    except ValueError:
        zero_idx = None
    print("delimiter_index:", zero_idx)

    # Heuristics for message extraction
    msg_bytes = None
    if zero_idx is not None and zero_idx + 1 < len(b):
        msg_bytes = b[zero_idx + 1 :]
    else:
        # Fallback: assume message is at the end (as in this repo demos)
        msg_bytes = b.rstrip(b"\x00")
        # If everything is non-zero, keep last few bytes as the likely message
        if msg_bytes == b:
            # Heuristic: 32 bytes tail snapshot as message window
            tail = min(64, len(b))
            msg_bytes = b[-tail:]

    # Print message views
    print("message_hex:", msg_bytes.hex())
    print("message_ascii:", safe_ascii(msg_bytes))

    # Trailing diagnostics
    tlen = min(args.trailing_len, len(b))
    print("tail_hex:", b[-tlen:].hex())
    print("tail_ascii:", safe_ascii(b[-tlen:]))

    if args.find:
        idx = msg_bytes.find(args.find.encode("utf-8"))
        print(f"find('{args.find}'):", idx)

if __name__ == "__main__":
    main()
