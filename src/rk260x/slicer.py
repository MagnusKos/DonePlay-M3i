#!/usr/bin/env python3
"""Backward-slice harvester: extract (W, H, addr) from draw-call sites.

Convention (empirically established from confirmed sites):
  - call target 0x1996 (module code) / 0x1980 (resident) = DisplayPicture
  - W  is loaded into r6 as an immediate (movl/movh) shortly before call
  - H  is pushed onto the stack (st?/stdu to r12) or held in r5/r10
  - addr32 lives in an even register pair, built as:
        movl rA,lo / movh rA,hi  &  movl rB,lo2 / movh rB,hi2  (pair const)
        or  shll.e/sub.e/add.e chains (index * stride + base)
  - x, y are other small immediates nearby (not harvested for the map)

The slice walks backwards from the call over a linear window (no `ret`
crossing), tracking the last write of each register.
"""
import re

MOVLI = re.compile(r'^movl r(\d+), (\d+)$')
MOVHI = re.compile(r'^movh r(\d+), (\d+)$')
MOVI = re.compile(r'^mov r(\d+), (-?\d+)$')
MOVRR = re.compile(r'^mov r(\d+), r(\d+)$')
PUSH = re.compile(r'^st\S* r(\d+), r(?:12|1)\b')
EXTE = re.compile(r'^(\w+)\.e r(\d+), r(\d+) \[ext-pair\]$')
CALLR = re.compile(r'^call r(\d+)$')
CALLI = re.compile(r'^call (-?\d+)$')


def slice_site(ins, i, window=64):
    """ins: list of (addr, text); i: index of the call. Returns dict with
    w, h (ints or None), addr (dict: const | base+scale*sym)."""
    ca, ct = ins[i]
    regs16 = {}          # reg -> int (final value at call, from immediates)
    pair_base = {}       # even reg -> known const feeding it via add.e
    pushed = []          # stack-pushed constants (order: earlier->later)
    sym = {}             # even reg -> symbolic (base, scale) not resolved
    start = max(0, i - window)
    for a, t in ins[start:i + 1]:
        if t.startswith('ret'):
            regs16.clear(); pair_base.clear(); pushed.clear(); sym.clear()
        if m := MOVLI.match(t):
            r = int(m.group(1))
            regs16[r] = ((regs16.get(r, 0) & 0xFF00) | int(m.group(2))) & 0xFFFF
            continue
        if m := MOVHI.match(t):
            r = int(m.group(1))
            regs16[r] = ((regs16.get(r, 0) & 0x00FF) | (int(m.group(2)) << 8)) & 0xFFFF
            continue
        if m := MOVI.match(t):
            regs16[int(m.group(1))] = int(m.group(2)) & 0xFFFF
            continue
        if m := MOVRR.match(t):
            r, s = int(m.group(1)), int(m.group(2))
            if s in regs16:
                regs16[r] = regs16[s]
            else:
                regs16.pop(r, None)
            continue
        if m := PUSH.match(t):
            r = int(m.group(1))
            pushed.append(regs16.get(r))
            continue
        if m := EXTE.match(t):
            op, rd, rs = m.group(1), int(m.group(2)), int(m.group(3))
            if rs % 2 == 0 and rs in regs16 and (rs + 1) in regs16:
                # known const pair feeds rd
                pair_base[rd] = (regs16[rs + 1] << 16) | regs16[rs]
            elif rd in pair_base and rs in sym:
                # base + scale*idx accumulates
                b, s = sym.pop(rs)
                pair_base[rd] = pair_base.pop(rd, 0) + 0  # keep base only
            # note index-scaled adds: shll.e rX, k before add.e => scale 2^k
            if op == 'shll' and rd % 2 == 0:
                # look ahead handled by caller loop; store scale hint
                pass
            continue
        # any other instruction: drop the first reg operand's constness
        mm = re.match(r'^\S+\.?[a-z]*\s+r(\d+)', t)
        if mm and not t.startswith(('bc.', 'bra', 'call', 'st', 'nop', 'ret')):
            regs16.pop(int(mm.group(1)), None)

    w = regs16.get(6)
    h = None
    for v in reversed(pushed):
        if v is not None and 8 <= v <= 352:
            h = v
            break
    if h is None:
        h = regs16.get(10) if regs16.get(10) and 8 <= regs16.get(10) <= 352 else None
    if h is None and regs16.get(5) and 8 <= regs16.get(5) <= 352:
        h = regs16.get(5)
    # address: prefer explicit 32-bit const built across (rA, rA+1)
    addr = None
    for r in (10, 8, 4, 2, 0):
        lo, hi = regs16.get(r), regs16.get(r + 1)
        if lo is not None and hi is not None:
            V = (hi << 16) | lo
            if 0x100 <= V < 0x1000000 and not (V & 0xFFFF) == 0x1996:
                addr = {'const': V}
                break
    if addr is None:
        for rd, v in pair_base.items():
            if 0x100 <= v < 0x1000000:
                addr = {'const': v}
                break
    return {'site': hex(ca), 'w': w, 'h': h, 'addr': addr,
            'smalls': sorted({v for v in regs16.values()
                              if v is not None and 1 <= v <= 352})}
