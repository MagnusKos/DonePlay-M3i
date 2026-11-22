#!/usr/bin/env python3
"""rk_ecc.py — RockChip RK26xx NAND spare ECC (reversed from Consumer.exe
FUN_00408460). 3 bytes per 512-byte block (Hamming-style, inverted output).

Spare group layout per 512B data block (16 bytes):
  [0:4]  = FF FF FF FF marker (special blocks: bytes 2-3 = "id")
  [4:8]  = (layout detail: written by tool, usually derived 4B)
  [8:11] = ecc512(block)  -- verified 8619/8621 on captured corpus
  [11:16]= remaining spare bytes
Full 2048B page spare = 4 such groups (64 bytes).
"""

import struct

M = 0xFFFFFFFF


def ecc512(data: bytes) -> bytes:
    """ECC over one 512-byte block -> 3 bytes (exact port of FUN_00408460)."""
    if len(data) != 512:
        raise ValueError("ecc512 needs exactly 512 bytes")
    words = struct.unpack("<128I", data)
    p = q = r = s = 0
    t = 0
    flip = False
    for i in range(16):
        w = (words[i*8] ^ words[i*8+1] ^ words[i*8+2] ^ words[i*8+3]
             ^ words[i*8+4] ^ words[i*8+5] ^ words[i*8+6] ^ words[i*8+7])
        p ^= words[i*8+1] ^ words[i*8+3] ^ words[i*8+5] ^ words[i*8+7]
        q ^= words[i*8+2] ^ words[i*8+3] ^ words[i*8+6] ^ words[i*8+7]
        r ^= words[i*8+4] ^ words[i*8+5] ^ words[i*8+6] ^ words[i*8+7]
        s ^= w
        x = w ^ (w >> 16)
        x ^= x >> 8
        x ^= x >> 4
        x = (x >> 2 & 3) ^ (x & 3)
        if x == 1 or x == 2:
            t ^= i
            flip = not flip
    def fold(v, mode):
        v = (v ^ (v >> 16)) & M
        if mode == "r":
            v = (v ^ (v << 8)) & M
            v = (v ^ (v >> 4)) & M
            v = (v ^ (v >> 2)) & M
        elif mode == "q":
            v = (v ^ (v >> 8)) & M
            v = (v ^ (v << 4)) & M
            v = (v ^ (v * 4)) & M
        else:  # p
            v = (v ^ (v >> 8)) & M
            v = (v ^ (v << 4)) & M
            v = (v ^ (v >> 2)) & M
        return v
    L10 = fold(r, "r")
    U11 = fold(q, "q")
    U10 = fold(p, "p")
    u1 = ((s >> 16) ^ (s >> 24)) & M
    u1 = (u1 ^ (u1 >> 4)) & M
    u1 = (u1 ^ (u1 * 4)) & M
    u2 = (((s & 0xFF00FF00) >> 16) ^ (s & 0xFF00FF00)) & M
    u2 = ((u2 >> 8) ^ (u2 >> 12)) & M
    u2 = (u2 ^ (u2 >> 2)) & M
    u4 = ((s & 0xF0F0F0F0) ^ ((s & 0xF0F0F0F0) << 16)) & M
    u4 = (u4 ^ (u4 >> 8)) & M
    u4 = (u4 ^ (u4 * 4)) & M
    u5 = ((s & 0xCCCCCCCC) ^ ((s & 0xCCCCCCCC) << 16)) & M
    u5 = (u5 ^ (u5 >> 8)) & M
    u6 = ((u5 << 2) ^ (u5 >> 2)) & M
    u7 = ((s & 0xAAAAAAAA) ^ ((s & 0xAAAAAAAA) << 16)) & M
    u7 = (u7 ^ (u7 >> 8)) & M
    u7 = (u7 ^ (u7 >> 4)) & M
    out = 0
    out ^= (L10 & 0x100) << 1
    out ^= L10 & 0x200
    out ^= (U11 & 0x40) << 1
    out ^= U11 & 0x80
    out ^= (U10 & 0x10) << 1
    out ^= U10 & 0x20
    out ^= (u1 & 4) << 1
    out ^= u1 & 8
    out ^= (u2 & 1) << 1
    out ^= u2 & 2
    out ^= (u4 & 0x400000) << 1
    out ^= u4 & 0x800000
    out ^= (u6 & 0x100000) << 1
    out ^= u6 & 0x200000
    out ^= ((((t & 8) << 1 | t & 4) << 1 | t & 2) << 1 | t & 1) << 11
    out ^= (u7 & 0x20000) << 2
    out ^= u7 & 0x80000
    # NOTE: ~(uVar10 | (flip ? uVar10^0xAAAAAA : uVar10) >> 1)
    right = (out ^ 0xAAAAAA) if flip else out
    val = (~(out | (right >> 1))) & M
    return bytes([val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF])


if __name__ == "__main__":
    import sys
    data = open(sys.argv[1], "rb").read()
    off = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0
    print(ecc512(data[off:off+512]).hex())


# ---------------------------------------------------------------------------
# Full 16-byte spare group via solved GF(2) affine map (basis from capture).
# Group layout: [FF FF FF FF][x4][ecc512 3B][y5]; total page spare = 4 groups.

import os as _os

_BASIS = None

def _load_basis():
    global _BASIS
    if _BASIS is not None:
        return _BASIS
    here = _os.path.dirname(_os.path.abspath(__file__))
    for path in (_os.path.join(here, "spare_basis.bin"),
                 _os.path.join(here, "..", "..", "derived", "spare_basis.bin"),
                 _os.path.join("derived", "spare_basis.bin")):
        if _os.path.exists(path):
            break
    if not _os.path.exists(path):
        raise RuntimeError("spare_basis.bin missing (run: rkx derive <capture.pcapng>)")
    with open(path, "rb") as f:
        C = f.read(16)
        n = int.from_bytes(f.read(4), "little")
        basis = {}
        for _ in range(n):
            vin = f.read(512)
            vout = f.read(16)
            hb = int.from_bytes(vin, "little").bit_length() - 1
            basis[hb] = (vin, vout)
    _BASIS = (C, basis)
    return _BASIS


def spare_group(block512: bytes) -> bytes:
    """Full 16-byte spare group for a 512-byte data block."""
    if block512 == b"\xff" * 512:
        return b"\xff" * 16   # erased block -> erased spare
    C, basis = _load_basis()
    vin = block512
    out = bytearray(16)
    def xor16(a, b):
        for i in range(16):
            a[i] ^= b[i]
    while True:
        v = int.from_bytes(vin, "little")
        if v == 0:
            break
        hb = v.bit_length() - 1
        if hb not in basis:
            raise ValueError("block not in basis span (should not happen)")
        bin_, bout = basis[hb]
        vin = bytes(x ^ y for x, y in zip(vin, bin_))
        xor16(out, bout)
    return bytes(a ^ b for a, b in zip(bytes(out), C))


def page_spare(page2048: bytes) -> bytes:
    """Full 64-byte spare for a 2048-byte page (4 groups)."""
    return b"".join(spare_group(page2048[i*512:(i+1)*512]) for i in range(4))
