#!/usr/bin/env python3
"""Pragmatic ZSP400 disassembler (encoding from LSI ZSP400 Technical Manual,
Tables 8.12-8.21). Decodes 16-bit words; extended (.e) instructions consume
two words. Output is best-effort but sufficient for pattern-finding."""

import struct, sys

COND = ['z','nz','ge','lt','gt','le','v','nv','c','nc','r','r','lp2','lp2','lp0','lp0']
OP0 = ['mac','macn','mul','muln','mac2','cmacr','dmac','cmaci']*2
OP1_LD = {0:'ld',8:'lddu',9:'ldu',10:'ldu',11:'lddu',12:'ldx',13:'ldxu',14:'ldu',15:'ldu'}
OP1_ST = {0:'st',8:'stdu',9:'stu',10:'stu',11:'stdu',12:'stx',13:'stxu',14:'stu',15:'stu'}
OP2 = ['add','cmp','shll','shrl','shla','shra','sub','norm','and','or','xor','not','abs','min','max','neg']
OP4 = ['addsi','cmp','shll','shrl','shla','shra','mov','call','bitc','bits','biti','bitt','bitc','bits','biti','bitt']
OP5 = {(0,0,0):'round.e',(0,0,1):'cmp.e',(0,1,0):'shll.e',(0,1,1):'shrl.e',(1,0,0):'shla.e',(1,0,1):'shra.e',(1,1,0):'addc.e',(1,1,1):'subc.e'}
OP6 = {0:'revb',15:'nop'}

def sx(v, bits):
    m = 1 << (bits-1)
    return (v ^ m) - m

def disasm_word(w, nextw=None):
    """Decode one 16-bit word; returns (text, words_consumed)."""
    op = w >> 12
    b = f"{w:04x}"
    if op == 0x0:
        imm = sx(w & 0x7FF, 11)
        return f"bra {imm}", 1
    if op == 0x1:
        imm = sx(w & 0x7FF, 11)
        return f"call {imm}", 1
    if op == 0x2:
        return f"movl r{(w>>8)&0xF}, {w&0xFF}", 1
    if op == 0x3:
        return f"movh r{(w>>8)&0xF}, {w&0xFF}", 1
    if op == 0x4:
        cond = (w >> 8) & 7
        inv = (w >> 11) & 1
        imm = sx(w & 0xFF, 8)
        return f"bc.{COND[cond*2+inv]} {imm}", 1
    if op in (0x5, 0xE):
        o = (w >> 8) & 0xF
        ab = '.b' if w & 0x800 else '.a'
        return f"{OP0[o]}{ab} r{(w>>4)&0xF}, r{w&0xF}", 1
    if op == 0x6:
        o = (w >> 8) & 0xF
        rx, ry = (w>>4)&0xF, w&0xF
        mn = OP1_ST.get(o, f"st?")
        if o == 0:
            return f"st r{rx}, r{ry}", 1
        off = {8:'+2',9:'+1',10:'+2',11:'-2',14:'-2',15:'-1'}.get(o,'x')
        return f"{mn} r{rx}, r{ry}, {off}", 1
    if op == 0x7:
        o = (w >> 8) & 0xF
        rx, ry = (w>>4)&0xF, w&0xF
        mn = OP1_LD.get(o, f"ld?")
        if o == 0:
            return f"ld r{rx}, (r{ry}+0)", 1
        off = {8:'+2',9:'+1',10:'+2',11:'-2',14:'-2',15:'-1'}.get(o,'x')
        return f"{mn} r{rx}, (r{ry}{off})", 1
    if op == 0x8:
        o = (w >> 8) & 0xF
        return f"{OP2[o]} r{(w>>4)&0xF}, r{w&0xF}", 1
    if op == 0x9:
        # extended alu: op3(4) rX.e(3) 0 rY.e(3) 0, consumes two words
        o = (w >> 8) & 0xF
        return f"{OP2[o]}.e r{(w>>5)&7}, r{(w>>1)&7} [ext-pair]", 2
    if op == 0xA:
        o = (w >> 8) & 0xF
        imm = sx(w & 0xF, 4)
        if o == 6: return f"mov r{(w>>4)&0xF}, {imm}", 1
        if o == 7: return f"call r{(w>>4)&0xF}", 1
        if o in (8,9,10,11): return f"{OP4[o]} r{(w>>4)&0xF}, {imm&0xF}", 1
        return f"{OP4[o]} r{(w>>4)&0xF}, {imm}", 1
    if op == 0xB:
        sub = (w >> 8) & 0xF
        if w == 0xBF01: return "ret", 1
        if w == 0xBF02: return "reti", 1
        if sub <= 7:
            key = ((w>>10)&1, (w>>9)&1, (w>>8)&1)
            mn = OP5.get(key, 'alu.e?')
            if key == (0,0,1): return f"cmp.e r{(w>>5)&7}, {sx(w&0xF,4)}", 1
            if key in ((0,1,0),(0,1,1),(1,0,0),(1,0,1)): return f"{mn} r{(w>>5)&7}, {w&0xF}", 1
            return f"{mn} r{(w>>5)&7}, r{(w>>1)&7}", 1
        if sub == 8: return f"mov r{w&0xF}, c{(w>>4)&0xF}", 1
        if sub == 9: return f"mov r{w&0xF}, c{((w>>4)&0xF)+16}", 1
        if sub == 0xA: return f"mov c{(w>>4)&0xF}, r{w&0xF}", 1
        if sub == 0xB: return f"mov c{((w>>4)&0xF)+16}, r{w&0xF}", 1
        if sub == 12: return f"mov r{(w>>4)&0xF}, r{w&0xF}", 1
        return f"reserved_{b}", 1
    if op == 0xC:
        o = (w >> 8) & 0xF
        mn = OP6.get(o, 'misc?')
        if o == 0xF and (w & 0xFF) == 0: return "nop", 1
        return f"{mn} r{(w>>4)&0xF}, {w&0xF}", 1
    if op in (0xD,):
        return f"mov{'h' if w&0x0800 else 'l'} c{(w>>8)&7}, {w&0xFF}", 1
    if op == 0xF:
        return f"reserved_{b}", 1
    return f"?_{b}", 1

def disasm(data, base=0, stop_words=None):
    words = struct.unpack(">%dH" % (len(data)//2), data[:len(data)//2*2])
    i = 0
    lines = []
    while i < len(words):
        w = words[i]
        nw = words[i+1] if i+1 < len(words) else None
        txt, n = disasm_word(w, nw)
        raw = " ".join(f"{words[i+k]:04x}" for k in range(n) if i+k < len(words))
        lines.append(f"{base + i*2:06x}: {raw:12s} {txt}")
        i += n
    return lines

if __name__ == "__main__":
    data = open(sys.argv[1], "rb").read()
    base = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0
    lines = disasm(data, base)
    print("\n".join(lines))
