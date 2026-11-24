"""Unit tests for automap family expansion (expand_families) and the
adjacency-containment purge in curate()."""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'src'))

from rk260x.automap import expand_families, curate  # noqa: E402


def smooth_slot(w, h, color=0x1234):
    """Raster with identical rows (vsmooth == 1.0) and >= 5 distinct
    column colors (passes the colors>=5 gate)."""
    row = bytearray()
    for x in range(w):
        c = (color + x * 0x0101) & 0xFFFF
        row += bytes([c >> 8, c & 0xFF])
    return bytes(row) * h


def garbage_slot(w, h, seed=0):
    """Deterministic noisy raster: low vsmooth, many colors."""
    out = bytearray()
    x = seed
    for _ in range(w * h):
        x = (x * 1103515245 + 12345) & 0xFFFF
        out += bytes([x >> 8, x & 0xFF])
    return bytes(out)


class TestExpandFamilies(unittest.TestCase):
    def _fw(self, *slots):
        return b''.join(slots)

    def test_sharp_drop_stops(self):
        w, h = 8, 4
        # seed + 3 good slots + garbage at k=4
        fw = self._fw(smooth_slot(w, h, 0x1111), smooth_slot(w, h, 0x2222),
                      smooth_slot(w, h, 0x3333), smooth_slot(w, h, 0x4444),
                      garbage_slot(w, h, 1))
        seed = {'name': 'seed', 'offset': 0, 'width': w, 'height': h}
        new, meta = expand_families(fw, [seed], [])
        offs = [i['offset'] for i in new]
        self.assertEqual(offs, [w * h * 2 * k for k in (1, 2, 3)])
        self.assertEqual(len(meta), 1)
        self.assertEqual(meta[0]['added'], 3)

    def test_trusted_overlap_stops(self):
        w, h = 8, 4
        stride = w * h * 2
        fw = self._fw(*[smooth_slot(w, h, 0x1000 + k) for k in range(4)])
        seed = {'name': 'seed', 'offset': 0, 'width': w, 'height': h}
        # trusted image starts inside slot k=2
        trusted = [(2 * stride + 4, 2 * stride + 8)]
        new, _ = expand_families(fw, [seed], trusted)
        offs = [i['offset'] for i in new]
        self.assertEqual(offs, [stride])          # k=1 only

    def test_walks_through_mapped_members(self):
        w, h = 8, 4
        stride = w * h * 2
        fw = self._fw(*[smooth_slot(w, h, 0x2000 + k) for k in range(5)])
        seed = {'name': 'seed', 'offset': 0, 'width': w, 'height': h}
        mapped = {'name': 'm1', 'offset': stride, 'width': w, 'height': h}
        new, _ = expand_families(fw, [seed, mapped], [])
        offs = [i['offset'] for i in new]
        self.assertEqual(offs, [2 * stride, 3 * stride, 4 * stride])
        for i in new:
            self.assertEqual(i['source'], 'progression')
            self.assertIn('family', i)
            self.assertEqual(i['family']['stride'], stride)

    def test_sym_site_corroboration(self):
        w, h = 8, 4
        fw = self._fw(*[smooth_slot(w, h, 0x3000 + k) for k in range(3)])
        seed = {'name': 'seed', 'offset': 0, 'width': w, 'height': h}
        sym = [{'site': '0x1', 'w': w, 'h': h, 'addrsym': 'lo=...'}]
        new, _ = expand_families(fw, [seed], [], sym_sites=sym)
        self.assertTrue(new)
        self.assertEqual(new[0]['family']['sym_sites'], 1)


class TestCurateRules(unittest.TestCase):
    def test_adjacency_purge_of_reinjected_fake(self):
        # two abutting trusted images, a fake automap entry inside the span
        a = {'name': 'A', 'offset': 0, 'width': 10, 'height': 10,
             'source': 'verdict:hand'}
        b = {'name': 'B', 'offset': 200, 'width': 10, 'height': 10,
             'source': 'verdict:hand'}
        fake = {'name': 'fake', 'offset': 50, 'width': 5, 'height': 5,
                'source': 'automap', 'callsites': 3}
        out, purged = curate([a, b, fake], [a, b])
        names = {i['name'] for i in out}
        self.assertNotIn('fake', names)
        self.assertEqual(purged, 1)

    def test_rejects_never_enter(self):
        a = {'name': 'A', 'offset': 0, 'width': 4, 'height': 4,
             'source': 'automap'}
        out, _ = curate([a], [], [{'offset': 0, 'reason': 'garbage'}])
        self.assertEqual(out, [])

    def test_same_offset_hypothesis_flag(self):
        p = {'name': 'p', 'offset': 0, 'width': 8, 'height': 8,
             'source': 'automap', 'callsites': 4}
        q = {'name': 'q', 'offset': 0, 'width': 6, 'height': 6,
             'source': 'automap', 'callsites': 1}
        out, _ = curate([p, q], [])
        prim = [i for i in out if not i['source'].endswith('?hypothesis')]
        hyp = [i for i in out if i['source'].endswith('?hypothesis')]
        self.assertEqual(len(prim), 1)
        self.assertEqual(prim[0]['name'], 'p')
        self.assertEqual(len(hyp), 1)
        self.assertEqual(hyp[0]['name'], 'q')


if __name__ == '__main__':
    unittest.main()
