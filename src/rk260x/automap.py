#!/usr/bin/env python3
"""automap.py — automatically map UI images in RK260x firmware (.rfw).

v0.1: infrastructure + reconnaissance. Produces a per-device JSON image map
(same format as hand-made maps) once the draw-call harvester is complete.

Pipeline (design):
  1. rfw.py: decrypt firmware blocks (code block + plaintext resource tail).
  2. zspdis: disassemble the code block (runtime = rfw_offset - RUNTIME_BASE).
  3. Identify the firmware's DisplayPicture(x, y, xsize, ysize, addr) twin:
     signature-match against code compiled from the SDK source with the
     ORIGINAL toolchain (scripts/zsp_build.py) — "compile what you want to
     find".
  4. Harvest call sites: recover (x, y, w, h, addr32) from the argument
     setup at each site. 32-bit values live in EVEN REGISTER PAIRS
     (r4:r5, r6:r7, ...); some args are stack-passed (stdu/stu pushes).
  5. Calibrate the resource base against a hand-made map if provided;
     emit the device map (JSON, rk260x-image-map/1).

Known-so-far (M3i, Firmware M3i 070930.rfw):
  - candidate hot call targets: 0x0932 (60x), 0x1666 (36x), 0x03c0 (28x);
    a confirmed fullscreen draw sequence sits at rfw 0x3126..0x315e
    (movl r10,176 / movl r6,220 / pair arithmetic add.e / stack args /
    call), LCD status register = c9 (polled via `mov r0,c9; bitt r0,5`).
  - CAUTION: bare `movl rX,11` hits (40x) are LCD wait-loop counters, not
    image widths. Only function-level analysis is trustworthy.
"""
import argparse, json, re, struct, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from rk260x import rfw as rfwmod
from rk260x.zspdis import disasm
from rk260x.imgmap import MAP_FORMAT

RUNTIME_BASE = 0x1408  # rfw offset - runtime IRAM address (main fw @ 0x88)


KEY_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           '..', '..', 'data', 'xor_key_512.bin')


def load_code_block(path, keyfile=None):
    """Decrypt and return (code_bytes, rfw_start_offset) of the main code
    block (the anchor-172-style block found by find_anchors)."""
    data = open(path, 'rb').read()
    key = rfwmod.load_key(keyfile or KEY_DEFAULT)
    anchors = rfwmod.find_anchors(data, key)
    # main code block: the biggest anchor block that starts early and holds
    # the vector signature; fall back to the classic 0x1490/172 layout.
    best = None
    for off, anchor, is_entry in anchors:
        if off >= len(data):
            continue
        blob = rfwmod.xor_block(data[off:off + 0x200], key, anchor, offset=off)
        # vector-table signature: reti+nop words
        score = sum(1 for i in range(0, min(len(blob), 0x110), 2)
                    if blob[i:i+2] == b'\xbf\x02')
        if best is None or score > best[0]:
            best = (score, off, anchor)
    off, anchor = best[1], best[2]
    end = min(len(data), 0x100000)  # code+data region heuristic
    code = rfwmod.xor_block(data[off:end], key, anchor, offset=off)
    return code, off


def instructions(code, rfw_base):
    pat = re.compile(r'^([0-9a-f]{6}):\s+(?:[0-9a-f]{4}(?: [0-9a-f]{4})?)\s+(.*)$')
    return [(int(m.group(1), 16), m.group(2).strip())
            for ln in disasm(code, rfw_base) if (m := pat.match(ln))]


def call_histogram(ins):
    """Track movl/movh/mov-built register constants; histogram call targets."""
    regs = {}
    calls = []
    movl = re.compile(r'^movl r(\d+), (\d+)$')
    movh = re.compile(r'^movh r(\d+), (\d+)$')
    movi = re.compile(r'^mov r(\d+), (-?\d+)$')
    callr = re.compile(r'^call r(\d+)$')
    other = re.compile(r'^(\S+)\s+r(\d+)')
    for addr, t in ins:
        if m := movl.match(t):
            r = int(m.group(1)); regs[r] = (regs.get(r, (0, None))[0], int(m.group(2))); continue
        if m := movh.match(t):
            r = int(m.group(1)); regs[r] = (int(m.group(2)), regs.get(r, (None, 0))[1]); continue
        if m := movi.match(t):
            r = int(m.group(1)); v = int(m.group(2)) & 0xFFFF
            regs[r] = ((v >> 8) & 0xFF, v & 0xFF); continue
        if m := callr.match(t):
            r = int(m.group(1))
            hi, lo = regs.get(r, (None, None))
            if hi is not None and lo is not None:
                calls.append((addr, (hi << 8) | lo))
            continue
        if (m := other.match(t)) and not t.startswith(('movl', 'movh', 'call', 'bc.')):
            regs.pop(int(m.group(2)), None)
    return calls


def recon(path, keyfile):
    code, off = load_code_block(path, keyfile)
    ins = instructions(code, off)
    calls = call_histogram(ins)
    from collections import Counter
    hist = Counter(t for _, t in calls)
    print(f"code block: rfw 0x{off:x}..0x{off+len(code):x}, {len(ins)} instructions")
    print(f"direct calls with resolved target: {len(calls)}")
    for tgt, cnt in hist.most_common(12):
        print(f"  0x{tgt:04x}  {cnt}x")
    return code, off, ins, hist


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog='automap')
    ap.add_argument('firmware', help='.rfw firmware container')
    ap.add_argument('-o', '--out', help='output device map (JSON)')
    ap.add_argument('--calibrate', help='existing map (JSON) to validate '
                                        'against and to resolve the base')
    ap.add_argument('--recon', action='store_true',
                    help='reconnaissance: call-target histogram only')
    args = ap.parse_args(argv)
    return run(args.firmware, args.out, args.calibrate, args.recon)

def run(path, out=None, calibrate=None, do_recon=False):
    code, off, ins, hist = recon_(path, None)
    if do_recon:
        return
    # v0.1: emit an empty device map as a placeholder for the pipeline
    m = {"format": MAP_FORMAT, "device": None,
         "firmware": os.path.basename(path),
         "pixel_format": "BE-BGR565",
         "images": [],
         "note": "automap v0.1 reconnaissance — harvester pending; "
                 f"top call targets: "
                 + ", ".join(f"0x{t:04x}({c}x)" for t, c in hist.most_common(5))}
    out = out or os.path.splitext(path)[0] + '.map.json'
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(m, f, indent=1, ensure_ascii=False)
    print(f"wrote {out}")


def recon_(path, keyfile):
    return recon(path, keyfile)




if __name__ == '__main__':
    main()
