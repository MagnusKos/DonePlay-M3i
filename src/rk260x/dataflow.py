#!/usr/bin/env python3
"""dataflow.py — per-function CFG + abstract dataflow harvester for RK260x.

Replaces the linear backward window (slicer.py) as automap's default harvest
path.  Model (semantics verified against M3i firmware disasm + LSI ZSP400
manual, see REA-Session/NOTES.md "AUTOMAP" sections):

* one CFG per code region (resident block / decrypted overlay run); basic
  blocks split at bra/bc targets, ret and post-branch/call boundaries
* forward abstract interpretation over the region CFG; non-draw call edges
  are followed (interprocedural param flow), worklist fixpoint with pass cap
* value domain for scalars r0-r15:
    SConst(v)              16-bit constant
    SSym(base, scale, var) base + scale * <runtime value var>
    SParam(key)            named unknown loaded from frame slot `key`
    SP(k)                  stack-pointer-relative pointer (r12 + k words)
    SProjLo/SProjHi(p)     low/high half projection of a 32-bit pair value
  pairs (even rX = {rX+1 hi, rX lo} per manual "SHLL.E" page):
    PConst(v), PSym(base, scale, var)
* memory = frame slots keyed ('sp', word_off) / ('r', reg, word_off);
  pointer regs tracked as SP+k normalize keys so caller stores flow into
  callee loads through call edges
* ZSP400 convention (verified from the draw function epilogue at rfw 0x2E12):
  callees save/restore every register they clobber -> calls preserve r0-r15
  except r4/r6.  Draw-call args live at fixed frame slots:
  h -> (SP,1), addr lo/hi -> (SP,2)/(SP,3)  [calibrated on baseline sites]
* branch/call immediates are word offsets relative to the instruction's own
  address:  target = addr + imm*2   (verified on the boot-anim loop)
* `st?`/`ld?` op1 field (zspdis prints 'x') is the word offset of the slot;
  decoded here from the raw word — zspdis.py output stays unchanged.
"""
import re
from collections import defaultdict

DRAW_TARGETS = (0x1996, 0x1980)      # runtime addresses of DisplayPicture(+thunk)
# Draw-call argument conventions — calibrated on the 134 linear-baseline
# sites (artifacts/automap/s1): H lands at frame slot ('sp',1) or ('sp',3);
# the address is an explicitly pushed pair at slots 2/3 when the pair
# register would be clobbered, else a live register pair (r10/r4/r2/r8/r0).
# Kept as named constants for S2 family expansion.
DRAW_H_SLOT = 1
DRAW_ADDR_LO_SLOT = 2
DRAW_ADDR_HI_SLOT = 3
MAX_STEPS = 20000
MAX_BLOCK_VISITS = 8

# ---------------------------------------------------------------- parsing
LINE_RE = re.compile(
    r'^([0-9a-f]{6}):\s+((?:[0-9a-f]{4})(?:\s+[0-9a-f]{4})?)\s+(.*)$')

R_MOVLI = re.compile(r'^movl r(\d+), (\d+)$')
R_MOVHI = re.compile(r'^movh r(\d+), (\d+)$')
R_MOVI = re.compile(r'^mov r(\d+), (-?\d+)$')
R_MOVR = re.compile(r'^mov r(\d+), r(\d+)$')
R_MOVRC = re.compile(r'^mov r(\d+), c\d+$')          # from control reg
R_MOVCR = re.compile(r'^mov c\d+, r(\d+)$')          # to control reg
R_MOVLC = re.compile(r'^mov[lh] c\d+, \d+$')         # control const load
R_ADDSI = re.compile(r'^addsi r(\d+), (-?\d+)$')
R_ALUI = re.compile(r'^(add|sub|shll|shrl|shla|shra|and|or|xor|bits|bitc|biti|bitt) r(\d+), (-?\d+)$')
R_ALUR = re.compile(r'^(add|sub|shll|shrl|shla|shra|and|or|xor|min|max|not|abs|neg|norm|revb) r(\d+), r(\d+)$')
R_MAC = re.compile(r'^(mac\w*|mul\w*|cmac\w*|dmul\w*)(\.[ab]) r(\d+), r(\d+)$')
R_EXT_R = re.compile(r'^(add|sub|and|or|xor|shll|shrl|shla|shra|addc|subc|norm|not|abs|min|max|neg)\.e r(\d+), r(\d+)')
R_EXT_I = re.compile(r'^(shll|shrl|shla|shra)\.e r(\d+), (\d+)$')
R_LDST = re.compile(r'^(ld|st)\S*')
R_BRA = re.compile(r'^bra (-?\d+)$')
R_BC = re.compile(r'^bc\.\w+ (-?\d+)$')
R_CALLI = re.compile(r'^call (-?\d+)$')
R_CALLR = re.compile(r'^call r(\d+)$')
R_RET = re.compile(r'^reti?$')


def parse_lines(lines):
    """disasm() output -> list of dicts: addr, text, words, and for ld/st the
    decoded slot (base_reg, word_off) from the raw word."""
    out = []
    for ln in lines:
        m = LINE_RE.match(ln.strip())
        if not m:
            continue
        addr = int(m.group(1), 16)
        words = [int(w, 16) for w in m.group(2).split()]
        ins = {'addr': addr, 'text': m.group(3).strip(), 'words': words}
        t = ins['text']
        w = words[0]
        if R_LDST.match(t) and (w >> 12) in (6, 7):
            op1 = (w >> 8) & 0xF
            ry = w & 0xF
            # op1 0 -> +0; 1..7 -> word offset ('?' forms); 8..15 decoded in text
            if op1 == 0:
                off = 0
            elif 1 <= op1 <= 7:
                off = op1
            else:
                mo = re.search(r'([+-]\d+)', t)
                off = int(mo.group(1)) if mo else 0
            ins['slot'] = (ry, off)
        out.append(ins)
    return out


# ---------------------------------------------------------------- values
class SConst:
    __slots__ = ('v',)
    def __init__(self, v): self.v = v & 0xFFFF
    def eq(self, o): return isinstance(o, SConst) and o.v == self.v
    def __repr__(self): return f'{self.v}'

class SSym:
    """base + scale * var   (e.g. 176 - y  ==  SSym(176, -1, 'y'))"""
    __slots__ = ('base', 'scale', 'var')
    def __init__(self, base, scale, var):
        self.base, self.scale, self.var = base, scale, var
    def eq(self, o):
        return (isinstance(o, SSym) and o.base == self.base
                and o.scale == self.scale and o.var == self.var)
    def __repr__(self):
        if self.scale == 1:
            return f'{self.base}+{self.var}' if self.base else self.var
        if self.scale == -1:
            return f'{self.base}-{self.var}' if self.base else f'-{self.var}'
        return f'{self.base}{self.scale:+}*{self.var}'

class SParam:
    __slots__ = ('key',)
    def __init__(self, key): self.key = key
    def eq(self, o): return isinstance(o, SParam) and o.key == self.key
    def __repr__(self): return f'?{self.key}'

class SP:
    __slots__ = ('k',)
    def __init__(self, k): self.k = k
    def eq(self, o): return isinstance(o, SP) and o.k == self.k
    def __repr__(self): return f'SP{self.k:+}'

class SProj:
    __slots__ = ('pair', 'hi')
    def __init__(self, pair, hi): self.pair, self.hi = pair, hi
    def eq(self, o):
        return isinstance(o, SProj) and o.hi == self.hi and (
            self.pair is None and o.pair is None or
            self.pair is not None and o.pair is not None and o.pair.eq(self.pair))
    def __repr__(self):
        return f'{self.pair!r}[{"hi" if self.hi else "lo"}]'

class PConst:
    __slots__ = ('v',)
    def __init__(self, v): self.v = v & 0xFFFFFFFF
    def eq(self, o): return isinstance(o, PConst) and o.v == self.v
    def __repr__(self): return f'{self.v:#x}'

class PSym:
    __slots__ = ('base', 'scale', 'var')
    def __init__(self, base, scale, var):
        self.base, self.scale, self.var = base, scale, var
    def eq(self, o):
        return (isinstance(o, PSym) and o.base == self.base
                and o.scale == self.scale and o.var == self.var)
    def __repr__(self): return f'{self.base:#x}+{self.scale}*{self.var}'


def meet(a, b):
    if a is None and b is None: return None
    if a is None: return b
    if b is None: return a
    return a if a.eq(b) else None


ALU_FN = {
    'add': lambda a, b: a + b, 'sub': lambda a, b: a - b,
    'and': lambda a, b: a & b, 'or': lambda a, b: a | b,
    'xor': lambda a, b: a ^ b,
    'shll': lambda a, b: a << b, 'shrl': lambda a, b: a >> b,
    'shla': lambda a, b: a << b, 'shra': lambda a, b: a >> b,
    'min': min, 'max': max,
}


def alu(op, a, b):
    """Safe ALU fold: bad shift counts (signed-imm encodings) -> None."""
    if op in ('shll', 'shrl', 'shla', 'shra') and not (0 <= b <= 15):
        return None
    return ALU_FN[op](a, b)


# ---------------------------------------------------------------- state
class State:
    __slots__ = ('regs', 'pairs', 'mem')

    def __init__(self):
        self.regs = [None] * 16
        self.pairs = {}     # even reg -> PConst/PSym/None-explicit
        self.mem = {}       # key -> scalar value or SProj

    def copy(self):
        s = State()
        s.regs = list(self.regs)
        s.pairs = dict(self.pairs)
        s.mem = dict(self.mem)
        return s

    def _sig(self):
        return (tuple(map(repr, self.regs)),
                tuple(sorted((k, repr(v)) for k, v in self.pairs.items())),
                tuple(sorted((k, repr(v)) for k, v in self.mem.items())))

    def meet(self, other):
        for i in range(16):
            self.regs[i] = meet(self.regs[i], other.regs[i])
        for k in set(self.pairs) | set(other.pairs):
            self.pairs[k] = meet(self.pairs.get(k), other.pairs.get(k))
        for k in set(self.mem) | set(other.mem):
            self.mem[k] = meet(self.mem.get(k), other.mem.get(k))

    def set_reg(self, r, v):
        self.regs[r] = v
        self.pairs.pop(r & ~1, None)

    def pair_kill(self, r):
        self.pairs[r] = None
        self.regs[r] = None
        self.regs[r + 1] = None

    def pair_get(self, r):
        if r % 2:
            return None
        if r in self.pairs:
            return self.pairs[r]
        lo, hi = self.regs[r], self.regs[r + 1]
        if isinstance(lo, SConst) and isinstance(hi, SConst):
            return PConst((hi.v << 16) | lo.v)
        return None

    def pair_set(self, r, v):
        assert v is not None
        self.pairs[r] = v
        self.regs[r] = SProj(v, False)
        self.regs[r + 1] = SProj(v, True)


def norm_key(state, base_reg, off):
    """slot key for mem; SP-tracked bases normalize to ('sp', k+off)."""
    b = state.regs[base_reg]
    if isinstance(b, SP):
        return ('sp', b.k + off)
    if base_reg == 12:
        return ('sp', off)
    return ('r', base_reg, off)


# ---------------------------------------------------------------- transfer
def step(state, ins):
    t = ins['text']

    if m := R_MOVLI.match(t):
        r, v = int(m.group(1)), int(m.group(2))
        old = state.regs[r]
        state.set_reg(r, SConst((old.v & 0xFF00) | v)
                      if isinstance(old, SConst) else SConst(v))
        return
    if m := R_MOVHI.match(t):
        r, v = int(m.group(1)), int(m.group(2))
        old = state.regs[r]
        state.set_reg(r, SConst((old.v & 0x00FF) | (v << 8))
                      if isinstance(old, SConst) else SConst(v << 8))
        return
    if m := R_MOVI.match(t):
        state.set_reg(int(m.group(1)), SConst(int(m.group(2))))
        return
    if m := R_MOVR.match(t):
        r, s = int(m.group(1)), int(m.group(2))
        state.set_reg(r, state.regs[s])
        return
    if m := R_MOVRC.match(t):
        state.set_reg(int(m.group(1)), None)
        return
    if R_MOVCR.match(t) or R_MOVLC.match(t) or t == 'nop' or R_RET.match(t):
        return
    if t.startswith('cmp'):
        return                                   # flags only, no register write

    if m := R_ADDSI.match(t):
        r, imm = int(m.group(1)), int(m.group(2))
        v = state.regs[r]
        if isinstance(v, SConst):
            state.set_reg(r, SConst(v.v + imm))
        elif isinstance(v, SP):
            state.regs[r] = SP(v.k + imm)
        elif isinstance(v, SSym):
            state.set_reg(r, SSym(v.base + imm, v.scale, v.var))
        elif isinstance(v, SParam):
            state.set_reg(r, SSym(imm, 1, repr(v)))
        else:
            state.set_reg(r, None)
        return
    if m := R_ALUI.match(t):
        op, r, imm = m.group(1), int(m.group(2)), int(m.group(3))
        if op in ('bits', 'bitc', 'biti'):
            state.set_reg(r, None)
            return
        if op == 'bitt':
            return
        v = state.regs[r]
        if isinstance(v, SConst):
            nv = alu(op, v.v, imm)
            state.set_reg(r, SConst(nv) if nv is not None else None)
        elif isinstance(v, SSym) and op in ('add', 'sub'):
            state.set_reg(r, SSym(v.base + (imm if op == 'add' else -imm), v.scale, v.var))
        elif isinstance(v, SParam) and op in ('add', 'sub'):
            state.set_reg(r, SSym(imm if op == 'add' else -imm, 1, repr(v)))
        else:
            state.set_reg(r, None)
        return
    if m := R_ALUR.match(t):
        op, r, s = m.group(1), int(m.group(2)), int(m.group(3))
        a, b = state.regs[r], state.regs[s]
        if op in ('not', 'abs', 'neg', 'norm', 'revb'):
            f = {'not': lambda x: ~x, 'abs': abs, 'neg': lambda x: -x}.get(op)
            state.set_reg(r, SConst(f(a.v)) if (f and isinstance(a, SConst)) else None)
            return
        if isinstance(a, SConst) and isinstance(b, SConst):
            nv = alu(op, a.v, b.v)
            state.set_reg(r, SConst(nv) if nv is not None else None)
        elif isinstance(a, SP) and isinstance(b, SConst) and op == 'add':
            state.regs[r] = SP(a.k + b.v)        # pointer + const
        elif isinstance(a, SSym) and isinstance(b, SConst) and op in ('add', 'sub'):
            state.set_reg(r, SSym(a.base + (b.v if op == 'add' else -b.v), a.scale, a.var))
        elif isinstance(b, SSym) and isinstance(a, SConst) and op == 'add':
            state.set_reg(r, SSym(a.v + b.base, b.scale, b.var))
        elif isinstance(a, SConst) and isinstance(b, SParam) and op in ('add', 'sub'):
            # 176 - y  ->  SSym(176, -1, y)
            state.set_reg(r, SSym(a.v, 1 if op == 'add' else -1, repr(b)))
        else:
            state.set_reg(r, None)
        return

    if m := R_MAC.match(t):
        # .a accumulates into pair {r1 r0}, .b into {r3 r2}; operands are inputs
        acc = 0 if m.group(2) == '.a' else 2
        rx, ry = int(m.group(3)), int(m.group(4))
        vx, vy = state.regs[rx], state.regs[ry]
        prod = None
        if isinstance(vx, SConst) and isinstance(vy, SConst):
            prod = PConst(vx.v * vy.v)
        elif isinstance(vx, (SParam, SSym)) and isinstance(vy, SConst):
            prod = PSym(0, vy.v, repr(vx))
        elif isinstance(vy, (SParam, SSym)) and isinstance(vx, SConst):
            prod = PSym(0, vx.v, repr(vy))
        cur = state.pairs.get(acc)
        if prod is None:
            state.pair_kill(acc)
        elif isinstance(cur, PConst) and isinstance(prod, PConst):
            state.pair_set(acc, PConst(cur.v + prod.v))
        else:
            state.pair_set(acc, prod)
        return

    if m := R_EXT_R.match(t):
        op, rd, rs = m.group(1), int(m.group(2)), int(m.group(3))
        opn = {'addc': 'add', 'subc': 'sub'}.get(op, op)
        a, b = state.pair_get(rd), state.pair_get(rs)
        if opn in ('add', 'sub'):
            if isinstance(a, PConst) and isinstance(b, PConst):
                state.pair_set(rd, PConst(alu(opn, a.v, b.v)))
            elif isinstance(a, PConst) and isinstance(b, PSym) and opn == 'add':
                state.pair_set(rd, PSym(a.v + b.base, b.scale, b.var))
            elif isinstance(a, PSym) and isinstance(b, PConst) and opn == 'add':
                state.pair_set(rd, PSym(a.base + b.v, a.scale, a.var))
            elif a is None and isinstance(b, (PConst, PSym)):
                if opn == 'add':
                    state.pair_set(rd, b)
                else:
                    state.pair_kill(rd)
            else:
                state.pair_kill(rd)
        elif opn in ('shll', 'shrl', 'shla', 'shra'):
            sh = state.regs[rs]
            if isinstance(a, PConst) and isinstance(sh, SConst):
                nv = alu(opn, a.v, sh.v & 0xF)
                if nv is not None:
                    state.pair_set(rd, PConst(nv))
                else:
                    state.pair_kill(rd)
            else:
                state.pair_kill(rd)
        else:
            state.pair_kill(rd)
        return
    if m := R_EXT_I.match(t):
        op, rd, imm = m.group(1), int(m.group(2)), int(m.group(3))
        a = state.pair_get(rd)
        if isinstance(a, PConst):
            nv = alu(op, a.v, imm)
            if nv is not None:
                state.pair_set(rd, PConst(nv))
            else:
                state.pair_kill(rd)
        elif isinstance(a, PSym):
            state.pair_set(rd, PSym(a.base, a.scale << imm, a.var))
        else:
            state.pair_kill(rd)
        return

    if 'slot' in ins:
        ry, off = ins['slot']
        key = norm_key(state, ry, off)
        if t.startswith('ld'):
            rx = int(re.match(r'^\S+\?? r(\d+)', t).group(1))
            if t.startswith('lddu'):
                lo = state.mem.get((key, 0))
                hi = state.mem.get((key, 1))
                if isinstance(lo, SConst) and isinstance(hi, SConst):
                    state.pair_set(rx & ~1, PConst((hi.v << 16) | lo.v))
                else:
                    state.pair_kill(rx & ~1)
            else:
                if (key, 0) in state.mem:
                    state.set_reg(rx, state.mem[(key, 0)])
                else:
                    state.set_reg(rx, SParam(key))
        else:
            rx = int(re.match(r'^\S+\?? r(\d+)', t).group(1))
            if t.startswith('stdu'):
                pv = state.pair_get(rx & ~1)
                if pv is not None:
                    state.mem[(key, 0)] = SProj(pv, False)
                    state.mem[(key, 1)] = SProj(pv, True)
                else:
                    state.mem[(key, 0)] = state.regs[rx]
                    state.mem.pop((key, 1), None)
                if isinstance(state.regs[ry], SP):
                    state.regs[ry] = SP(state.regs[ry].k + off)
            else:
                state.mem[(key, 0)] = state.regs[rx]
                if t.startswith('stu') and isinstance(state.regs[ry], SP):
                    state.regs[ry] = SP(state.regs[ry].k + off)
        return

    if R_BRA.match(t) or R_BC.match(t) or R_CALLI.match(t) or R_CALLR.match(t):
        return

    mm = re.match(r'^\S+\.?[a-z]*\s+r(\d+)', t)
    if mm:
        state.set_reg(int(mm.group(1)), None)


def call_effects(state):
    """post-call state: callee-saved ABI keeps r0-r15 except r4/r6; the
    callee reuses the arg frame slots at/below the caller's pushes."""
    st = state.copy()
    st.set_reg(4, None)
    st.set_reg(6, None)
    for k in range(-8, 16):
        st.mem.pop(('sp', k), None)
    return st


# ---------------------------------------------------------------- CFG
class Region:
    def __init__(self, ins_list, name=''):
        self.ins = ins_list
        self.name = name
        self.by_addr = {i['addr']: n for n, i in enumerate(ins_list)}
        self._analyze()

    def _target(self, ins):
        m = R_BRA.match(ins['text']) or R_BC.match(ins['text']) \
            or R_CALLI.match(ins['text'])
        return ins['addr'] + int(m.group(1)) * 2 if m else None

    def _analyze(self):
        ins, by = self.ins, self.by_addr
        leaders = {ins[0]['addr']} if ins else set()
        for n, i in enumerate(ins):
            tgt = self._target(i)
            if tgt is not None and tgt in by:
                leaders.add(tgt)
            if R_RET.match(i['text']) or tgt is not None or R_CALLR.match(i['text']):
                if n + 1 < len(ins):
                    leaders.add(ins[n + 1]['addr'])
        order = sorted(a for a in leaders if a in by)
        blocks, start = [], 0
        for L in order[1:]:
            n = by[L]
            blocks.append(ins[start:n])
            start = n
        if ins:
            blocks.append(ins[start:])
        self.blocks = blocks
        self.block_of = {}
        for bi, b in enumerate(blocks):
            for i in b:
                self.block_of[i['addr']] = bi

    def successors(self, block):
        last = block[-1]
        t = last['text']
        n = self.by_addr[last['addr']] + 1
        if R_RET.match(t):
            return []
        succs = []
        if not R_BRA.match(t) and n < len(self.ins):
            succs.append(self.block_of[self.ins[n]['addr']])
        # branch targets only — call edges are propagated in run_region with
        # the PRE-call state (post-call state must not leak into callees)
        m = R_BRA.match(t) or R_BC.match(t)
        if m:
            tgt = last['addr'] + int(m.group(1)) * 2
            if tgt in self.by_addr:
                bi = self.block_of[tgt]
                if bi not in succs:
                    succs.append(bi)
        return succs


def run_region(ins_list, name='', draw_targets=DRAW_TARGETS):
    """Worklist abstract interpretation. Returns {call_addr: state} at every
    call site whose (const-tracked) target is a draw function.

    Entry seeding: the region start PLUS every orphan block (no predecessors)
    gets a fresh state — stripped-code regions begin with data, and functions
    are only discoverable by their ret boundaries / call targets."""
    reg = Region(ins_list, name)
    if not reg.blocks:
        return {}
    preds = {bi: set() for bi in range(len(reg.blocks))}
    for bi, b in enumerate(reg.blocks):
        for sbi in reg.successors(b):
            preds[sbi].add(bi)
    IN = {bi: None for bi in range(len(reg.blocks))}
    for bi in range(len(reg.blocks)):
        if bi == reg.block_of[reg.ins[0]['addr']] or not preds[bi]:
            s = State()
            s.regs[12] = SP(0)
            IN[bi] = s
    sites = {}
    visits = defaultdict(int)
    work = [bi for bi in range(len(reg.blocks)) if IN[bi] is not None]
    steps = 0
    while work and steps < MAX_STEPS:
        bi = work.pop(0)
        st = IN[bi]
        if st is None:
            continue
        visits[bi] += 1
        steps += 1
        for ins in reg.blocks[bi]:
            t = ins['text']
            if m := R_CALLR.match(t):
                tv = st.regs[int(m.group(1))]
                if isinstance(tv, SConst) and tv.v in draw_targets:
                    sites[ins['addr']] = st.copy()
                step(st, ins)
                st = call_effects(st)
                continue
            if m := R_CALLI.match(t):
                tgt = ins['addr'] + int(m.group(1)) * 2
                step(st, ins)
                callee = st.copy()
                st = call_effects(st)
                if tgt in reg.by_addr:            # follow non-draw call edges
                    tb = reg.block_of[tgt]
                    if IN[tb] is None:
                        IN[tb] = callee
                        work.append(tb)
                    elif visits[tb] < MAX_BLOCK_VISITS:
                        before = IN[tb]._sig()
                        IN[tb].meet(callee)
                        if IN[tb]._sig() != before:
                            work.append(tb)
                continue
            step(st, ins)
        for sbi in reg.successors(reg.blocks[bi]):
            out = st.copy()
            if IN[sbi] is None:
                IN[sbi] = out
                work.append(sbi)
            elif visits[sbi] < MAX_BLOCK_VISITS:
                before = IN[sbi]._sig()
                IN[sbi].meet(out)
                if IN[sbi]._sig() != before:
                    work.append(sbi)
    return sites


# ---------------------------------------------------------------- extraction
def val_int(v):
    return v.v if isinstance(v, SConst) else None


def extract_site(addr, st):
    """State at a draw call -> slicer-compatible dict + symbol annotations.

    Calibrated on the 134 linear-baseline sites (see artifacts/automap/s1):
      H  -> frame slot ('sp',1), else ('sp',3), else ('sp',0), else regs
      addr -> register pair r10/r4/r2/r8/r0 at call time, else slots 2/3
    """
    w = val_int(st.regs[6])
    h, hsym = None, None
    for k in (1, 3, 0, 2):
        v = st.mem.get((('sp', k), 0))
        iv = val_int(v)
        if iv is not None and 1 <= iv <= 352:
            h = iv
            break
        if isinstance(v, (SSym, SParam)) and hsym is None:
            hsym = repr(v)
    if h is None:
        for r in (5, 10, 0, 3):
            v = st.regs[r]
            if isinstance(v, SConst) and 8 <= v.v <= 352:
                h = v.v
                break
    addr_val, asym = None, None
    # 1) explicitly pushed pair at slots 2/3 (the deliberate addr push —
    #    beats register pairs, which may still hold the pre-index BASE)
    lo = st.mem.get((('sp', 2), 0))
    hi = st.mem.get((('sp', 3), 0))
    if isinstance(lo, SProj) and isinstance(hi, SProj) and lo.pair is not None \
            and lo.pair is hi.pair:
        if isinstance(lo.pair, PConst):
            addr_val = {'const': lo.pair.v}
        else:
            asym = repr(lo.pair)
    elif isinstance(lo, SConst) and isinstance(hi, SConst):
        V = (hi.v << 16) | lo.v
        if 0x100 <= V < 0x1000000 and (V & 0xFFFF) != 0x1996:
            addr_val = {'const': V}
    elif isinstance(lo, (SSym, SParam)) or isinstance(hi, (SSym, SParam)):
        asym = f'lo={lo!r} hi={hi!r}'
    # 2) register pairs at call time (calibrated priority)
    if addr_val is None and asym is None:
        for e in (10, 4, 2, 8, 0):
            p = st.pair_get(e)
            if isinstance(p, PConst) and 0x100 <= p.v < 0x1000000 \
                    and (p.v & 0xFFFF) != 0x1996:
                addr_val = {'const': p.v}
                break
            if isinstance(p, PSym) and asym is None:
                asym = repr(p)
    smalls = sorted({v.v for v in st.regs
                     if isinstance(v, SConst) and 1 <= v.v <= 352})
    out = {'site': hex(addr), 'w': w, 'h': h, 'addr': addr_val,
           'smalls': smalls, 'src': 'dataflow'}
    if hsym:
        out['hsym'] = hsym
    if asym:
        out['addrsym'] = asym
    return out


def harvest_dataflow(regions, draw_targets=DRAW_TARGETS):
    """regions: list of (name, parse_lines output). Returns site dicts."""
    out = []
    for name, ins in regions:
        try:
            sites = run_region(ins, name, draw_targets)
        except Exception as e:
            print(f'dataflow: region {name} failed: {e}')
            continue
        for a in sorted(sites):
            out.append(extract_site(a, sites[a]))
    return out
