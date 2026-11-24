"""Unit tests for the automap dataflow engine (src/rk260x/dataflow.py).

Instruction streams are written directly as (addr, raw_word, text) triples —
the same shapes zspdis produces — so the tests pin the engine's semantics
without touching firmware files.  Raw words matter for the ld/st '?' forms:
the engine decodes the slot offset from op1 (bits 11..8), so every ld?/st?
here carries its real encoding (e.g. 0x715a = ld? r5, (r10+1)).
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'src'))

from rk260x.dataflow import (  # noqa: E402
    parse_lines, run_region, extract_site, step, State, meet,
    SConst, SSym, SParam, SP, PConst, PSym)


def mk(addr, word, text):
    lines = [f'{addr:06x}: {word:04x}        {text}']
    return parse_lines(lines)[0]


class TestConsts(unittest.TestCase):
    def test_movl_movh_addsi(self):
        st = State()
        for t in ('movl r0, 184', 'movh r0, 1', 'addsi r0, 56'):
            step(st, mk(0x1000, 0, t))
        self.assertEqual(st.regs[0].v, 496)     # 0x1B8 + 56

    def test_movh_alone_is_byte(self):
        st = State()
        step(st, mk(0x1000, 0, 'movh r2, 25'))
        self.assertEqual(st.regs[2].v, 25 << 8)

    def test_meet_conflicting_consts(self):
        self.assertIsNone(meet(SConst(1), SConst(2)))
        self.assertEqual(meet(SConst(1), None).v, 1)
        self.assertIsNone(meet(SSym(176, -1, 'y'), SSym(170, -1, 'y')))


class TestSym(unittest.TestCase):
    def test_const_minus_param(self):
        st = State()
        step(st, mk(0x1000, 0, 'movl r0, 176'))
        step(st, mk(0x1002, 0x715a, 'ld? r5, (r10x)'))
        self.assertIsInstance(st.regs[5], SParam)
        step(st, mk(0x1004, 0, 'sub r0, r5'))
        v = st.regs[0]
        self.assertIsInstance(v, SSym)
        self.assertEqual((v.base, v.scale), (176, -1))

    def test_param_plus_const(self):
        st = State()
        step(st, mk(0x1000, 0x711a, 'ld? r1, (r10x)'))
        step(st, mk(0x1002, 0, 'addsi r1, 3'))
        v = st.regs[1]
        self.assertIsInstance(v, SSym)
        self.assertEqual((v.base, v.scale), (3, 1))


class TestFrameSlots(unittest.TestCase):
    def test_store_load_roundtrip_sp_normalized(self):
        st = State()
        st.regs[12] = SP(0)
        step(st, mk(0x1000, 0, 'mov r10, r12'))
        step(st, mk(0x1002, 0, 'addsi r10, 5'))
        step(st, mk(0x1004, 0, 'movl r1, 172'))
        step(st, mk(0x1006, 0x631a, 'st? r1, r10, x'))   # slot (r10,3) -> sp+8
        self.assertEqual(st.mem[(('sp', 8), 0)].v, 172)
        step(st, mk(0x1008, 0x731a, 'ld? r0, (r10x)'))   # load slot (r10,3)
        self.assertEqual(st.regs[0].v, 172)

    def test_pushed_pair_reconstructs(self):
        st = State()
        st.regs[12] = SP(0)
        step(st, mk(0x1000, 0, 'movl r0, 184'))
        step(st, mk(0x1002, 0, 'movh r0, 1'))              # r0 = 440
        step(st, mk(0x1004, 0, 'movl r1, 32'))             # r1 = 32
        step(st, mk(0x1006, 0, 'movl r4, 0'))
        step(st, mk(0x1008, 0, 'movl r5, 32'))
        step(st, mk(0x100a, 0x5401, 'mac2.a r1, r0'))      # pair{r1 r0} = 32*440
        step(st, mk(0x100c, 0x9104, 'add.e r0, r4 [ext-pair]'))  # += 32<<16
        step(st, mk(0x100e, 0x620c, 'st? r0, r12, x'))     # push lo @ slot2
        step(st, mk(0x1010, 0x631c, 'st? r1, r12, x'))     # push hi @ slot3
        site = extract_site(0x1000, st)
        self.assertEqual(site['addr'], {'const': 0x203700})


class TestCfg(unittest.TestCase):
    def test_branch_target_own_address(self):
        seq = [
            mk(0x1000, 0, 'nop'),
            mk(0x1002, 0, 'nop'),
            mk(0x1004, 0xfffd, 'bra -3'),      # -> 0x0ffe, out of region
            mk(0x1006, 0, 'nop'),
        ]
        from rk260x.dataflow import Region
        r = Region(seq, 't')
        self.assertEqual(len(r.blocks), 2)      # split after bra

    def test_loop_backedge_blocks_terminate(self):
        seq = [
            mk(0x2000, 0, 'mov r0, 5'),
            mk(0x2002, 0, 'addsi r1, 1'),
            mk(0x2004, 0, 'addsi r0, -1'),
            mk(0x2006, 0x41fd, 'bc.gt -2'),     # -> 0x2002
            mk(0x2008, 0, 'nop'),
        ]
        sites = run_region(seq, 't')            # must terminate (fixpoint)
        self.assertEqual(sites, {})

    def test_draw_site_extraction(self):
        seq = [
            mk(0x2000, 0, 'movl r6, 220'),
            mk(0x2002, 0, 'movh r6, 0'),
            mk(0x2004, 0, 'movl r0, 176'),
            mk(0x2006, 0, 'movh r0, 0'),
            mk(0x2008, 0x715a, 'ld? r5, (r10x)'),      # y = param
            mk(0x200a, 0, 'sub r0, r5'),               # h = 176 - y
            mk(0x200c, 0, 'movl r1, 10'),
            mk(0x200e, 0, 'movh r1, 34'),              # r1 = 0x220A
            mk(0x2010, 0x610c, 'st? r0, r12, x'),      # h  -> slot1
            mk(0x2012, 0x620c, 'st? r0, r12, x'),      # lo -> slot2
            mk(0x2014, 0x631c, 'st? r1, r12, x'),      # hi -> slot3
            mk(0x2016, 0, 'movl r0, 150'),
            mk(0x2018, 0, 'movh r0, 25'),              # r0 = 0x1996
            mk(0x201a, 0xa760, 'call r0'),
        ]
        sites = run_region(seq, 't')
        self.assertIn(0x201a, sites)
        site = extract_site(0x201a, sites[0x201a])
        self.assertEqual(site['w'], 220)
        self.assertIsNone(site['h'])            # symbolic: hsym carries it
        self.assertIn('hsym', site)
        self.assertIn('176', site['hsym'])
        self.assertIsNone(site['addr'])         # lo is a sym, hi const -> asym
        self.assertIn('addrsym', site)

    def test_draw_site_concrete(self):
        seq = [
            mk(0x3000, 0, 'movl r6, 220'),
            mk(0x3002, 0, 'movh r6, 0'),
            mk(0x3004, 0, 'movl r0, 144'),
            mk(0x3006, 0, 'movh r0, 0'),
            mk(0x3008, 0x610c, 'st? r0, r12, x'),      # h = 144 @ slot1
            mk(0x300a, 0, 'movl r0, 0'),               # lo lo byte
            mk(0x300c, 0, 'movh r0, 32'),              # lo = 0x2000
            mk(0x300e, 0x620c, 'st? r0, r12, x'),      # lo -> slot2
            mk(0x3010, 0, 'movl r1, 55'),
            mk(0x3012, 0, 'movh r1, 0'),               # hi = 0x37
            mk(0x3014, 0x631c, 'st? r1, r12, x'),      # hi -> slot3
            mk(0x3016, 0, 'movl r0, 150'),
            mk(0x3018, 0, 'movh r0, 25'),
            mk(0x301a, 0xa760, 'call r0'),
        ]
        sites = run_region(seq, 't')
        site = extract_site(0x301a, sites[0x301a])
        self.assertEqual((site['w'], site['h']), (220, 144))
        self.assertEqual(site['addr'], {'const': 0x372000})


class TestPairOps(unittest.TestCase):
    def test_mac_sym_scale(self):
        st = State()
        step(st, mk(0x1000, 0x711a, 'ld? r1, (r10x)'))  # index param
        step(st, mk(0x1002, 0, 'movl r0, 184'))
        step(st, mk(0x1004, 0, 'movh r0, 1'))           # r0 = 440
        step(st, mk(0x1006, 0x5401, 'mac2.a r1, r0'))
        p = st.pairs[0]
        self.assertIsInstance(p, PSym)
        self.assertEqual(p.scale, 440)

    def test_shll_e_doubles_scale(self):
        st = State()
        step(st, mk(0x1000, 0x711a, 'ld? r1, (r10x)'))
        step(st, mk(0x1002, 0, 'movl r0, 220'))
        step(st, mk(0x1004, 0x5401, 'mac2.a r1, r0'))   # idx*220
        step(st, mk(0x1006, 0xb4a2, 'shll.e r2, 2'))    # other pair <<2
        self.assertEqual(st.pairs[0].scale, 220)


if __name__ == '__main__':
    unittest.main()
