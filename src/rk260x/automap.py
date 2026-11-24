#!/usr/bin/env python3
"""automap.py — automatically map UI images in RK260x firmware (.rfw).

v0.2 — what works today (all verified on the M3i):
  * decrypt the code block (rfw.py anchors) and disassemble it (zspdis)
  * emulate the instruction stream: track register constants, register
    PAIRS (32-bit values), stack pushes; snapshot state at every call
  * translate flash logic addresses to .rfw file offsets using the
    flasher's own placement data (derived/full_stream.json +
    derived/page_template.json — the flash layout differs from file order!)
  * calibrate the image-region base (ImageLogicAddress) against a
    hand-made map; report per-site findings

Firmware facts this is built on (M3i, see REA-Session notes):
  - images are headerless BE-BGR565 rasters, exact-fit adjacent
  - the flash image region starts at flash 0x240000 (= file 0x4AE73A on
    the M3i; the translation is available through the page map)
  - there is NO table of contents: group addresses are computed at runtime
    as base + index * (w*h*2); absolute pair constants appear at draw
    sites (191 of 237 mined constants fall inside the image region)
  - confirmed draw function candidate: runtime 0x1980 (fullscreen draws);
    LCD status register: c9
"""
import argparse, json, os, re, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from rk260x import rfw as rfwmod
from rk260x.zspdis import disasm
from rk260x.imgmap import MAP_FORMAT, load_map

RUNTIME_BASE = 0x1408   # runtime = rfw_offset - RUNTIME_BASE (main fw @ 0x88)
KEY_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           '..', '..', 'data', 'xor_key_512.bin')
DERIVED_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               '..', '..', 'derived')


ALU = {'add': lambda a, b: a + b, 'sub': lambda a, b: a - b,
       'and': lambda a, b: a & b, 'or': lambda a, b: a | b,
       'xor': lambda a, b: a ^ b, 'shll': lambda a, b: a << b,
       'shrl': lambda a, b: (a & 0xFFFF) >> b, 'shla': lambda a, b: a << b,
       'shra': lambda a, b: a >> b}

movl = re.compile(r'^movl r(\d+), (\d+)$')
movh = re.compile(r'^movh r(\d+), (\d+)$')
movi = re.compile(r'^mov r(\d+), (-?\d+)$')
movrr = re.compile(r'^mov r(\d+), r(\d+)$')
callr = re.compile(r'^call r(\d+)$')
calli = re.compile(r'^call (-?\d+)$')
pushp = re.compile(r'^st\S* r(\d+), r12')
alu2 = re.compile(r'^(add|sub|and|or|xor|shll|shrl|shla|shra|mul|cmp|min|max|mac\w*|not|abs|neg|norm|round) r(\d+), r(\d+)(\.[ab])?$')
alui = re.compile(r'^(addsi|add|sub|shll|shrl|shla|shra|cmp|bits|bitc|biti|bitt) r(\d+), (-?\d+)$')
ldp = re.compile(r'^ld\S*\?? r(\d+),')
exte = re.compile(r'^(\w+)\.e r(\d+), r(\d+) \[ext-pair\]$')


def fold_e(op, dlo, dhi, slo, shi):
    a = (dhi << 16) | (dlo & 0xFFFF)
    b = (shi << 16) | (slo & 0xFFFF)
    if op == 'add':
        r = a + b
    elif op == 'sub':
        r = a - b
    elif op == 'shll':
        r = a << b
    elif op == 'mul':
        r = a * b
    else:
        return None
    return (r & 0xFFFF, (r >> 16) & 0xFFFF)


def harvest(ins):
    R, stack, sites = {}, [], []
    BASE = {}   # even reg -> known 32-bit const seen feeding it (add.e src)
    for addr, t in ins:
        if m := movl.match(t):
            r = int(m.group(1))
            R[r] = ((R.get(r, 0) & 0xFF00) | int(m.group(2))) & 0xFFFF
            continue
        if m := movh.match(t):
            r = int(m.group(1))
            R[r] = ((R.get(r, 0) & 0x00FF) | (int(m.group(2)) << 8)) & 0xFFFF
            continue
        if m := movi.match(t):
            R[int(m.group(1))] = int(m.group(2)) & 0xFFFF
            continue
        if m := movrr.match(t):
            r, s = int(m.group(1)), int(m.group(2))
            if R.get(s) is None:
                R.pop(r, None)
            else:
                R[r] = R[s]
            continue
        if m := pushp.match(t):
            stack.append(R.get(int(m.group(1))))
            if len(stack) > 12:
                stack.pop(0)
            continue
        if m := exte.match(t):
            op, rd, rs = m.group(1), int(m.group(2)), int(m.group(3))
            if all(R.get(x) is not None for x in (rd, rd + 1, rs, rs + 1)):
                res = fold_e(op, R[rd], R[rd + 1], R[rs], R[rs + 1])
                if res:
                    R[rd], R[rd + 1] = res
                    BASE[rd] = ((R[rd + 1] << 16) | R[rd])
                    continue
            # source pair known but dest not: remember const as base candidate
            if rs % 2 == 0 and all(R.get(x) is not None for x in (rs, rs + 1)):
                BASE[rd] = (R[rs + 1] << 16) | R[rs]
            if rd % 2 == 0:
                R.pop(rd, None)
                R.pop(rd + 1, None)
            continue
        if m := callr.match(t):
            sites.append((addr, R.get(int(m.group(1))), dict(R), list(stack), dict(BASE)))
            stack = []
            continue
        if m := calli.match(t):
            sites.append((addr, int(m.group(1)) & 0xFFFF, dict(R), list(stack), dict(BASE)))
            stack = []
            continue
        if m := alu2.match(t):
            op, d, s = m.group(1), int(m.group(2)), int(m.group(3))
            if op in ALU and R.get(d) is not None and R.get(s) is not None:
                R[d] = ALU[op](R[d], R[s]) & 0xFFFF
            else:
                R.pop(d, None)
            continue
        if m := alui.match(t):
            R.pop(int(m.group(2)), None)
            continue
        if m := ldp.match(t):
            R.pop(int(m.group(1)), None)
            continue
        if t.startswith('mov c') or t.startswith('bc.') or t.startswith('bra'):
            continue
        if t == 'nop' or t.startswith('ret'):
            continue
        if m := re.match(r'^mov r(\d+), c\d+', t):
            R.pop(int(m.group(1)), None)
    return sites




def load_code_block(path, keyfile=None):
    data = open(path, 'rb').read()
    key = rfwmod.load_key(keyfile or KEY_DEFAULT)
    anchors = rfwmod.find_anchors(data, key)
    best = None
    for off, anchor, is_entry in anchors:
        if off >= len(data):
            continue
        blob = rfwmod.xor_block(data[off:off + 0x200], key, anchor, offset=off)
        score = sum(1 for i in range(0, min(len(blob), 0x110), 2)
                    if blob[i:i+2] == b'\xbf\x02')
        if best is None or score > best[0]:
            best = (score, off, anchor)
    off, anchor = best[1], best[2]
    code = rfwmod.xor_block(data[off:min(len(data), 0x100000)], key, anchor, offset=off)
    return code, off


def instructions(code, rfw_base):
    pat = re.compile(r'^([0-9a-f]{6}):\s+((?:[0-9a-f]{4})(?: [0-9a-f]{4})?)\s+(.*)$')
    return [(int(m.group(1), 16), m.group(3).strip())
            for ln in disasm(code, rfw_base) if (m := pat.match(ln))]


def load_flash_map(derived_dir):
    """lba -> (rfw_off, m) from the flasher's stream+template."""
    stream = json.load(open(os.path.join(derived_dir, 'full_stream.json')))
    pmap = json.load(open(os.path.join(derived_dir, 'page_template.json')))
    wi, out = 0, {}
    for cdb_hex, payload_hex in stream:
        cdb = bytes.fromhex(cdb_hex)
        if cdb[0] == 5 and payload_hex:
            lba = int.from_bytes(cdb[2:6], 'big')
            if pmap[wi]:
                out[lba] = tuple(pmap[wi])
            wi += 1
    return out


def flash2file(lba2file, fba):
    lba = fba // 512
    if lba not in lba2file:
        return None
    off, m = lba2file[lba]
    d = fba - lba * 512
    return off + d if d < m else None


def site_values(site):
    """Extract (smalls, Vs) from a call-site snapshot."""
    addr, tgt, regs, st, base = site
    vals = [v for v in list(regs.values()) + st if v is not None]
    smalls = sorted({v for v in vals if 1 <= v <= 352})
    Vs = set()
    for r in range(0, 15, 2):
        a, b = regs.get(r), regs.get(r + 1)
        if a is not None and b is not None:
            V = (b << 16) | a
            if 0x100 <= V < 0x1000000:
                Vs.add(V)
    Vs |= {V for V in base.values() if 0x100 <= V < 0x1000000}
    return smalls, Vs




# ---------------- v1.0: full pipeline ----------------
import struct
from .slicer import slice_site, CALLR, CALLI


def code_score(blob):
    words = struct.unpack(f'>{len(blob)//2}H', blob[:len(blob)//2*2])
    s = 0
    for i in range(len(words) - 1):
        w, w2 = words[i], words[i + 1]
        if (w >> 12) == 2 and (w2 >> 12) == 3 and ((w >> 8) & 0xF) == ((w2 >> 8) & 0xF):
            s += 3
        if (w >> 12) == 0xA and ((w >> 8) & 0xF) == 7:
            s += 2
        if w in (0xBF01, 0xBF02):
            s += 2
    return s


def find_code_runs(rfw, key, start=0xFA88, end=0xE0000, thresh=30):
    """Overlay-module discovery: per 512B page pick the best-scoring
    XOR anchor; return contiguous same-anchor runs (>= 1.5 KB)."""
    pages = {}
    for page in range(start, end, 512):
        data = rfw[page:page + 512]
        if data.count(0) > 500 or data.count(0xFF) > 500:
            continue
        bs, ba = -1, None
        for anchor in range(512):
            blob = bytes(data[i] ^ key[(page + i - anchor) % 512] for i in range(512))
            sc = code_score(blob)
            if sc > bs:
                bs, ba = sc, anchor
        if bs > thresh:
            pages[page] = ba
    runs = []
    for p in sorted(pages):
        if runs and pages[p] == runs[-1][2] and p == runs[-1][1]:
            runs[-1][1] = p + 512
        else:
            runs.append([p, p + 512, pages[p]])
    return [r for r in runs if r[1] - r[0] >= 1536]


def decrypt_run(rfw, key, st, en, anchor):
    blob = bytearray()
    for p in range(st, en, 512):
        blob += bytes(rfw[p + i] ^ key[(p + i - anchor) % 512] for i in range(512))
    return bytes(blob)


def instructions_of(blob, base):
    pat = re.compile(r'^([0-9a-f]{6}):\s+((?:[0-9a-f]{4})(?: [0-9a-f]{4})?)\s+(.*)$')
    return [(int(m.group(1), 16), m.group(3).strip())
            for ln in disasm(blob, base) if (m := pat.match(ln))]


def harvest_draw_sites(rfw, key, draw_targets=(0x1996, 0x1980), linear=False):
    """Slice every call to the draw function across resident code and all
    discovered overlay modules. Returns list of slice dicts.
    Default: per-function CFG + dataflow (dataflow.py). linear=True: the
    original linear-window slicer (regression baseline)."""
    from rk260x.dataflow import parse_lines, harvest_dataflow
    res = rfwmod.xor_block(rfw[0x1490:0xFA88], key, 172, offset=0x1490)
    if not linear:
        regions = [('resident', parse_lines(disasm(res, 0x1490)))]
        seen = set()
        for st, en, anchor in find_code_runs(rfw, key):
            blob = decrypt_run(rfw, key, st, en, anchor)
            h = hash(blob)
            if h in seen:          # duplicate overlay module (0x54xxx == 0x12xxx)
                continue
            seen.add(h)
            regions.append((f'ovl_{st:06x}', parse_lines(disasm(blob, st))))
        dflow = harvest_dataflow(regions, draw_targets)
        # linear baseline preservation: every site the linear slicer folds
        # keeps its exact values (S1 no-regression contract); dataflow adds
        # the rest and attaches symbolic annotations.
        linsites = _harvest_linear(rfw, key, res, draw_targets)
        lin_full = {s['site']: s for s in linsites
                    if s['w'] and s['h'] and s['addr']}
        out = []
        for s in dflow:
            lf = lin_full.get(s['site'])
            if lf:
                merged = dict(lf)
                merged['src'] = 'linear+dataflow'
                for k in ('hsym', 'addrsym'):
                    if s.get(k):
                        merged[k] = s[k]
                out.append(merged)
            else:
                out.append(s)
        got = {s['site'] for s in out}
        for site, lf in sorted(lin_full.items()):
            if site not in got:
                out.append(dict(lf, src='linear-fallback'))
        return out
    results = []
    ins = instructions_of(res, 0x1490)
    sites = harvest(ins)
    results += _slice_targets(ins, sites, draw_targets)
    for st, en, anchor in find_code_runs(rfw, key):
        ins = instructions_of(decrypt_run(rfw, key, st, en, anchor), st)
        sites = harvest(ins)
        results += _slice_targets(ins, sites, draw_targets)
    return results


def _harvest_linear(rfw, key, res, draw_targets):
    ins = instructions_of(res, 0x1490)
    out = _slice_targets(ins, harvest(ins), draw_targets)
    for st, en, anchor in find_code_runs(rfw, key):
        ins = instructions_of(decrypt_run(rfw, key, st, en, anchor), st)
        out += _slice_targets(ins, harvest(ins), draw_targets)
    return out


def _slice_targets(ins, sites, draw_targets):
    out = []
    addr2idx = {a: i for i, (a, t) in enumerate(ins)}
    for addr, tgt, regs, st, base in sites:
        if tgt in draw_targets:
            j = addr2idx.get(addr)
            if j is not None:
                out.append(slice_site(ins, j))
    return out


def raster_quality(fw, fo, w, h):
    n = min(len(fw) // 2 - fo // 2, w * h)
    if n < w * 2:
        return 0.0, 0
    d = fw[fo:fo + w * h * 2]
    px = [(d[2 * i] << 8) | d[2 * i + 1] for i in range(n)]
    ve = sum(1 for i in range(w, n) if px[i] == px[i - w]) / (n - w)
    return ve, len(set(px))


def calibrate(slices, cal_images):
    """Find C (file offset of logic address 0): the candidate that turns
    the most DISTINCT harvested addresses into exact known-image offsets."""
    from collections import Counter
    votes = Counter()
    koff = {im['offset'] for im in cal_images}
    Vs = {s['addr']['const'] for s in slices if s['addr']}
    for im in cal_images:
        for V in Vs:
            C = im['offset'] - V
            if 0 <= C < 0x1000000:
                votes[C] += 0  # register candidate
    best, bestkey = None, None
    kwh = {im['offset']: (im['width'], im['height']) for im in cal_images}
    slices_rich = [s for s in slices if s['w'] and s['h'] and s['addr']]
    cands = set()
    for im in cal_images:
        for s in slices_rich:
            if im['width'] == s['w'] and im['height'] == s['h']:
                C = im['offset'] - s['addr']['const']
                if 0 <= C < 0x1000000:
                    cands.add(C)
    tail_start = 0xE0000  # family constant: plaintext resource tail
    for C in cands:
        hit = miss = 0
        for s in slices_rich:
            fo = s['addr']['const'] + C
            if fo in kwh:
                if kwh[fo] == (s['w'], s['h']):
                    hit += 1
                else:
                    miss += 1
        # plausibility: most predicted offsets must fall in the plaintext
        # resource tail (images are stored unencrypted there)
        ok_region = sum(1 for s in slices_rich
                        if tail_start <= s['addr']['const'] + C < 0x10000000)
        frac = ok_region / max(1, len(slices_rich))
        if frac < 0.9:
            continue
        key = (hit, -miss)
        if bestkey is None or key > bestkey:
            best, bestkey = C, key
    return best


def curate(cands, verdicts, rejects=()):
    """Operator-taught post-processing (verdict rounds 1-3, NOTES v1.0.1-v1.3):
    0. rejects: offsets vetoed by the operator never enter the map
    1. verdict overlay: entries from the operator-curated merged map win
       wholesale at their offset (names/sizes are operator-verified)
    2. adjacency containment: an automap entry strictly inside an exact-fit
       span between two abutting TRUSTED images is misassociated garbage
    3. same-offset different-size: highest call-site count is primary,
       others kept flagged '?hypothesis' for the operator
    4. automap-automap overlaps merge only when SAME size (lesson: greedy
       area-merges once ate the good 12x88 find)
    """
    rejects = {r['offset'] if isinstance(r, dict) else r for r in rejects}
    cands = [c for c in cands if c['offset'] not in rejects]
    def vtag(v):
        return 'verdict:' + (v.get('source') or 'hand')

    vd = {v['offset']: dict(v) for v in verdicts}
    out, seen_off = [], set()
    for c in cands:
        v = vd.get(c['offset'])
        if v is not None:
            e = dict(v)
            e['source'] = vtag(v)
            if not e.get('callsites') and c.get('callsites'):
                e['callsites'] = c['callsites']
            seen_off.add(c['offset'])
        else:
            e = dict(c)
        out.append(e)
    cand_offs = {c['offset'] for c in cands}
    for off, v in sorted(vd.items()):
        if off not in cand_offs:
            e = dict(v)
            e['source'] = vtag(v)
            out.append(e)

    trusted = sorted((e for e in out if str(e.get('source', '')).startswith('verdict')),
                     key=lambda e: e['offset'])
    spans = []
    for a, b in zip(trusted, trusted[1:]):
        if a['offset'] + a['width'] * a['height'] * 2 == b['offset']:
            spans.append((a['offset'],
                          b['offset'] + b['width'] * b['height'] * 2))
    kept = []
    purged = 0
    for e in out:
        if str(e.get('source', '')).startswith('verdict'):
            kept.append(e)
            continue
        s, t = e['offset'], e['offset'] + e['width'] * e['height'] * 2
        if any(s >= ps and t <= pt for ps, pt in spans):
            purged += 1
            continue
        kept.append(e)
    out = kept

    byoff = {}
    for e in out:
        byoff.setdefault(e['offset'], []).append(e)
    out = []
    for off in sorted(byoff):
        es = sorted(byoff[off],
                    key=lambda e: (-(e.get('callsites') or 0),
                                   e['width'] * e['height']))
        out.append(es[0])
        for e in es[1:]:
            if not str(e.get('source', '')).startswith('verdict'):
                e['source'] = str(e.get('source') or 'automap') + '?hypothesis'
            out.append(e)

    auto = [e for e in out
            if not str(e.get('source', '')).startswith('verdict')
            and not str(e.get('source', '')).endswith('?hypothesis')]
    drop = set()
    for i, a in enumerate(auto):
        if id(a) in drop:
            continue
        for b in auto[i + 1:]:
            if id(b) in drop or (a['width'], a['height']) != (b['width'], b['height']):
                continue
            ae = a['offset'] + a['width'] * a['height'] * 2
            be = b['offset'] + b['width'] * b['height'] * 2
            ov = min(ae, be) - max(a['offset'], b['offset'])
            if ov > 0.7 * (a['width'] * a['height'] * 2):
                a['callsites'] = (a.get('callsites') or 0) + (b.get('callsites') or 0)
                drop.add(id(b))
    out = [e for e in out if id(e) not in drop]
    out.sort(key=lambda e: e['offset'])
    return out, purged


def expand_families(rfw, images, trusted_spans, sym_sites=None, max_k=63,
                    min_area=16):
    """Family expansion — the VolBar progression method, generalized.

    From every mapped seed, walk exact-stride slots (stride = w*h*2,
    exact-fit tiling) and add slots while raster quality holds:
      * absolute floor: vsmooth > 0.10 and distinct colors >= 5
      * SHARP-DROP rule: vsmooth >= 0.55 * running median (VolBar:
        0.86-0.89 for k=0..40, 0.20 at k=41 -> stop, no k=41)
      * stop on file end, cap max_k, or when the slot region overlaps a
        TRUSTED span belonging to another image
      * slots already mapped with the same (w,h) are walked THROUGH
        (family passing through mapped territory), never re-added
    New slots get source='progression' with family metadata (seed, stride,
    k, per-slot raster stats) and sym-site corroboration counts.
    """
    import statistics
    existing = {(i['offset']): i for i in images}
    taken = set()
    sym_by_size = {}
    if sym_sites:
        for s in sym_sites:
            if s.get('w') and s.get('h'):
                key = (s['w'], s['h'])
                sym_by_size[key] = sym_by_size.get(key, 0) + 1
    new_images, fam_meta = [], []
    for seed in sorted(images, key=lambda i: i['offset']):
        w, h, so = seed['width'], seed['height'], seed['offset']
        if w * h < min_area:
            continue
        stride = w * h * 2
        ve0, c0 = raster_quality(rfw, so, w, h)
        if ve0 <= 0.10 or c0 < 5:
            continue                      # seed itself must be good
        ves = [ve0]
        added_here = 0
        for k in range(1, max_k + 1):
            off = so + k * stride
            if off + stride > len(rfw):
                break
            ex = existing.get(off)
            if ex is not None:
                if (ex['width'], ex['height']) == (w, h):
                    continue              # mapped family member: walk through
                break                     # region belongs to something else
            if any(off < te and off + stride > ts for ts, te in trusted_spans):
                break                     # overlaps trusted image: stop
            if off in taken:
                continue
            ve, colors = raster_quality(rfw, off, w, h)
            med = statistics.median(ves)
            if ve <= 0.10 or colors < 5 or ve < 0.55 * med:
                break                     # sharp drop / garbage
            ves.append(ve)
            taken.add(off)
            added_here += 1
            new_images.append({
                'name': f'prog_{off:06x}_{w}x{h}', 'offset': off,
                'width': w, 'height': h, 'source': 'progression',
                'family': {'seed': so, 'stride': stride, 'k': k,
                           'vsmooth': round(ve, 3), 'colors': colors,
                           'sym_sites': sym_by_size.get((w, h), 0)}})
        if added_here:
            fam_meta.append({'seed': so, 'w': w, 'h': h, 'stride': stride,
                             'added': added_here})
    return new_images, fam_meta


def run_full(path, out=None, calibrate_map=None, linear=False, verdicts=None,
             rejects=None):
    rfw = open(path, 'rb').read()
    key = rfwmod.load_key(KEY_DEFAULT)
    slices = harvest_draw_sites(rfw, key, linear=linear)
    rich = [s for s in slices if s['w'] and s['h'] and s['addr']]
    print(f"draw sites sliced: {len(slices)}, with full (w,h,addr): {len(rich)}"
          + ('  [linear baseline]' if linear else '  [dataflow]'))

    cal_images = load_map(calibrate_map)['images'] if calibrate_map else []
    # Hard calibration from the flasher's placement data when available:
    # the image region begins at flash 0x240000; its file offset is C.
    C = None
    if os.path.isdir(DERIVED_DEFAULT) and os.path.exists(os.path.join(DERIVED_DEFAULT, 'page_template.json')):
        try:
            lba2file = load_flash_map(DERIVED_DEFAULT)
            lba = 0x240000 // 512
            if lba in lba2file:
                C = lba2file[lba][0]
                print(f"calibration C = 0x{C:x} (from flash placement data: "
                      f"flash 0x240000 <-> file)")
        except Exception as e:
            print("flash-map calibration failed:", e)
    if C is None and cal_images:
        C = calibrate(rich, cal_images)
        print(f"calibration C = 0x{C:x} (statistical; LOW confidence)")
    if C is None:
        C = 0
        print("WARNING: no calibration source; using C=0")

    known = {im['offset']: im for im in cal_images}
    cands = {}
    for s in rich:
        V = s['addr']['const']
        fo = V + C
        if fo + s['w'] * s['h'] * 2 > len(rfw) or s['w'] * s['h'] < 16:
            continue
        cands[(fo, s['w'], s['h'])] = cands.get((fo, s['w'], s['h']), 0) + 1
    images, rejected = [], 0
    for (fo, w, h), n in sorted(cands.items()):
        if fo in known:
            im = dict(known[fo])
            im.update({'source': 'hand+automap', 'callsites': n})
        else:
            ve, colors = raster_quality(rfw, fo, w, h)
            if not (ve > 0.10 and colors >= 5):
                rejected += 1
                continue
            im = {'name': f'img_{fo:06x}_{w}x{h}', 'offset': fo, 'width': w,
                  'height': h, 'source': 'automap', 'callsites': n,
                  'confidence': 'raster-validated'}
        images.append(im)
    for im in cal_images:
        if im['offset'] not in {i['offset'] for i in images}:
            images.append(dict(im, source='hand'))
    # family expansion (S2): progression continuation from every seed
    trusted = list(cal_images)
    if verdicts:
        trusted += load_map(verdicts)['images']
    spans = sorted((i['offset'], i['offset'] + i['width'] * i['height'] * 2)
                   for i in trusted)
    fam_images, fam_meta = expand_families(rfw, images, spans,
                                           sym_sites=[s for s in slices
                                                      if s.get('addrsym')
                                                      or s.get('hsym')])
    images += fam_images
    purged = 0
    rejects_used = []
    if verdicts:
        vimgs = load_map(verdicts)['images']
        rj = []
        if rejects and os.path.exists(rejects):
            rj = json.load(open(rejects)).get('rejects', [])
        images, purged = curate(images, vimgs, rj)
    images.sort(key=lambda i: i['offset'])
    m = {'format': MAP_FORMAT, 'device': None,
         'firmware': os.path.basename(path), 'pixel_format': 'BE-BGR565',
         'logic_base_file_offset': C,
         'images': images,
         'families': fam_meta,
         'note': f'automap v1.0: {len(images)} images '
                 f'({sum(1 for i in images if i.get("source") == "automap")} new), '
                 f'{rejected} candidates rejected by raster validation'
                 + (f', {purged} purged by adjacency rule' if purged else '')}
    out = out or os.path.splitext(path)[0] + '.map.json'
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(m, f, indent=1, ensure_ascii=False)
    print(f"wrote {out}: {len(images)} images "
          f"({sum(1 for i in images if i.get('source') == 'automap')} new from automap)")
    return 0


def run(path, out=None, calibrate=None, do_recon=False, linear=False,
        verdicts=None, rejects=None):
    if calibrate is not None:
        return run_full(path, out, calibrate, linear=linear, verdicts=verdicts,
                        rejects=rejects)
    code, off = load_code_block(path)
    ins = instructions(code, off)
    sites = harvest(ins)
    print(f"code block rfw 0x{off:x}: {len(ins)} instructions, {len(sites)} call sites")

    derived = DERIVED_DEFAULT
    findings = []
    if os.path.isdir(derived) and os.path.exists(os.path.join(derived, 'full_stream.json')):
        lba2file = load_flash_map(derived)
        F0 = None
        if calibrate:
            cal = load_map(calibrate)['images']
            # calibrate: image region base = the flash address whose file
            # translation matches the smallest calibrated offset; scan
            # candidates from grid + refine
            cands = [0x240000]  # known-good on M3i; general search TODO
            best = None
            for f0 in cands:
                hits = 0
                for im in cal:
                    for lba, (o, m) in lba2file.items():
                        if o <= im['offset'] < o + m and f0 <= lba * 512:
                            pass
                # simpler validation below
            F0 = 0x240000
            matched = 0
            for site in sites:
                smalls, Vs = site_values(site)
                for V in Vs:
                    fo = flash2file(lba2file, F0 + V)
                    if fo is not None and any(im['offset'] == fo for im in cal):
                        matched += 1
                        break
            print(f"calibration: F0=0x{F0:x}, draw-site/known-image exact "
                  f"coincidences: {matched} (expect LOW: most images are "
                  f"drawn via runtime base+index*stride, not absolute consts)")
        for site in sites:
            smalls, Vs = site_values(site)
            for V in Vs:
                fo = flash2file(lba2file, (F0 or 0x240000) + V) if lba2file else None
                findings.append({
                    "site": hex(site[0]), "target": site[1] and hex(site[1]),
                    "w_h_candidates": smalls[:8], "addr_logic": hex(V),
                    "file_offset": fo and hex(fo)})
    m = {"format": MAP_FORMAT, "device": None,
         "firmware": os.path.basename(path),
         "pixel_format": "BE-BGR565",
         "images": [],
         "findings": findings[:2000],
         "note": "automap v0.2: sites harvested; full map needs the "
                 "draw-function dataflow pass (see REA-Session notes)"}
    out = out or os.path.splitext(path)[0] + '.map.json'
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(m, f, indent=1, ensure_ascii=False)
    print(f"wrote {out} ({len(findings)} site findings)")
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog='automap')
    ap.add_argument('firmware')
    ap.add_argument('-o', '--out')
    ap.add_argument('--calibrate')
    ap.add_argument('--verdicts',
                   help='operator-curated merged map (e.g. m3i_automap.json): '
                        'entries win wholesale; adjacency/dedup rules applied')
    ap.add_argument('--rejects',
                   help='rejects sidecar JSON (rk260x-image-rejects/1): '
                        'vetoed offsets never enter the map')
    ap.add_argument('--recon', action='store_true')
    ap.add_argument('--linear', action='store_true',
                    help='use the linear backward-window slicer (baseline) '
                         'instead of the CFG dataflow engine')
    args = ap.parse_args(argv)
    return run(args.firmware, args.out, args.calibrate, args.recon,
               linear=args.linear, verdicts=args.verdicts,
               rejects=args.rejects)


if __name__ == '__main__':
    main()
