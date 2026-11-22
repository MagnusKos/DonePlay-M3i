#!/usr/bin/env python3
"""
rfw.py — RockChip RK260x .rfw firmware container: parse, decrypt, extract.

Reverse-engineered from:
  * "Firmware M3i 070930.rfw" (Explay M3i, RK2606A)
  * RK2608A SDK demo RFWs (github.com/solderneer/SimpleMP4)
  * Consumer.exe / FirmwarePuller / RockUpdate*.img

Container model (see REA-Session/notes/rfw-format.md):
  0x000-0x037  plaintext header (magic ROCK260x2005VER5.00, date, "Rockchip")
  0x038-0x68F  encrypted config block (scheme unknown; NOT the global XOR key)
  0x690-       blocks, each XOR-encrypted with a global 512-byte key whose
               keystream RESTARTS at every block ("anchor" = keystream phase).
  resources >=~0xE0000 are plaintext (raw RGB565 images, fonts, tables).

Usage:
  python3 rfw.py info <file.rfw>
  python3 rfw.py extract <file.rfw> <outdir> [--key keyfile]
"""

import struct
import sys
import os

MAGIC = b"ROCK260x2005VER5.00"
PAGE = 512

# ZSP400 code signatures used for anchor detection
VEC_RECORD = bytes.fromhex("bf02" + "cf00" * 7)     # 02bf 00cf x7 (vector record)
ENTRY_MAGIC = bytes.fromhex("2cff3cbf")             # ff2c bf3c (code entry)


def load_key(keyfile):
    key = open(keyfile, "rb").read()
    if len(key) != PAGE:
        raise ValueError(f"key must be {PAGE} bytes, got {len(key)}")
    return key


def xor_block(data, key, anchor, offset=0):
    """Decrypt one block: plaintext[x] = data[x] ^ key[(x - anchor) % 512]."""
    n = len(data)
    out = bytearray(n)
    ka = (offset - anchor) % PAGE
    for i in range(n):
        out[i] = data[i] ^ key[(ka + i) % PAGE]
    return bytes(out)


def parse_header(data):
    if not data.startswith(MAGIC):
        raise ValueError("not a ROCK260x RFW file")
    h = {
        "magic": data[:16].decode("latin1"),
        "ver_string": data[0x11:0x17].decode("latin1"),
        "unknown_0x12": data[0x12],
        "date": (data[0x13], data[0x14], data[0x15]),   # yy? mm dd
        "time": (data[0x16], data[0x17], data[0x18]),
        "tail": data[0x19:0x1C].hex(),
        "vendor": data[0x1C:0x24].rstrip(b"\0").decode("latin1", "replace"),
        "field_0x30": data[0x30:0x34].hex(),
        "field_0x34": struct.unpack(">I", data[0x34:0x38])[0],
    }
    return h


def find_anchors(data, key, limit=0x200000):
    """Locate code blocks: search VEC_RECORD / ENTRY_MAGIC under all 512
    key rotations. Returns sorted list of (offset, anchor)."""
    hits = []
    region = data[:limit]
    for sig in (ENTRY_MAGIC, VEC_RECORD):
        for r in range(PAGE):
            pat = bytes(sig[t] ^ key[(r + t) % PAGE] for t in range(len(sig)))
            i = region.find(pat)
            while i >= 0:
                anchor = (i - r) % PAGE
                hits.append((i, anchor, sig is ENTRY_MAGIC))
                i = region.find(pat, i + 1)
    # merge duplicates at same offset
    out = {}
    for off, anchor, is_entry in hits:
        out.setdefault(off, (anchor, is_entry))
    return sorted((off, a, e) for off, (a, e) in out.items())


def find_zero_pads(data, key, min_run=32, limit=0x200000):
    """Encrypted zero runs == rotations of the key itself; each run pins a
    block anchor. Returns list of (offset, anchor) run starts."""
    raw = []
    region = data[:limit]
    for r in range(PAGE):
        pat = bytes(key[(r + t) % PAGE] for t in range(min_run))
        i = region.find(pat)
        while i >= 0:
            raw.append((i, (i - r) % PAGE))
            i = region.find(pat, i + 1)
    raw.sort()
    # group by anchor; within a group, keep only run starts (gap > run window)
    by_anchor = {}
    for off, anchor in raw:
        by_anchor.setdefault(anchor, []).append(off)
    starts = []
    for anchor, offs in by_anchor.items():
        offs.sort()
        last = None
        for off in offs:
            if last is None or off - last >= min_run:
                starts.append((off, anchor))
                last = off
    return sorted(starts)


def entropy(b):
    if not b:
        return 0.0
    freq = [0] * 256
    for x in b:
        freq[x] += 1
    e = 0.0
    n = len(b)
    import math
    for f in freq:
        if f:
            p = f / n
            e -= p * math.log2(p)
    return e


def cmd_info(path):
    data = open(path, "rb").read()
    h = parse_header(data)
    print("== RFW header")
    for k, v in h.items():
        print(f"  {k:14s} {v}")
    print(f"  size           {len(data)} (0x{len(data):x})")
    # default key shipped next to this file
    kd = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xor_key_512.bin")
    if os.path.exists(kd):
        key = load_key(kd)
        print("\n== XOR key found; code-block anchors:")
        for off, anchor, is_entry in find_anchors(data, key):
            kind = "ENTRY(ff2cbf3c)" if is_entry else "vector-record"
            print(f"  0x{off:06x}  anchor={anchor:3d}  {kind}")
        zp = find_zero_pads(data, key)
        print(f"\n== encrypted zero-runs (block paddings): {len(zp)}")
        for off, anchor in zp[:20]:
            print(f"  0x{off:06x}  anchor={anchor:3d}")


def cmd_extract(path, outdir, keyfile=None):
    data = open(path, "rb").read()
    os.makedirs(outdir, exist_ok=True)
    if keyfile is None:
        keyfile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xor_key_512.bin")
    key = load_key(keyfile)
    open(os.path.join(outdir, "header.bin"), "wb").write(data[:0x38])
    open(os.path.join(outdir, "config_block_0x38.bin"), "wb").write(data[0x38:0x690])

    blocks = [b for b in find_anchors(data, key) if b[2]]  # ENTRY-magic only
    idx = 0
    for off, anchor, _ in blocks:
        idx += 1
        name = f"code_block_{idx}_0x{off:06x}_a{anchor}.bin"
        blob = xor_block(data[off:], key, anchor, offset=off)
        open(os.path.join(outdir, name), "wb").write(blob[: 0x10000])
        print(f"extracted {name} (first 64KB, anchor {anchor})")
    print(f"\nresources >= 0xE0000 stored plaintext; whole tail written to tail_plain.bin")
    open(os.path.join(outdir, "tail_plain.bin"), "wb").write(data[0xE0000:])


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == "info" and len(sys.argv) == 3:
        cmd_info(sys.argv[2])
    elif cmd == "extract" and len(sys.argv) >= 4:
        cmd_extract(sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else None)
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
