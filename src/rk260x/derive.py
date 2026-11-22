"""Derive flasher artifacts (full_stream, page_template, spare_basis) from a capture."""
import json
import os
import struct
import sys


import json, os, struct, sys


def _data_fw():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, '..', '..', 'data', 'firmwares', 'Firmware M3i 070930.rfw')
    return p if os.path.exists(p) else 'Firmware M3i 070930.rfw'


def read_pkts(path):
    d = open(path, 'rb').read()
    if d[:4] == b'\x0a\x0d\x0d\x0a':
        off, pkts = 0, []
        while off + 12 <= len(d):
            btype, blen = struct.unpack_from('<II', d, off)
            if blen == 0 or off + blen > len(d): break
            if btype == 6:
                iface, ts_hi, ts_lo, caplen, origlen = struct.unpack_from('<IIIII', d, off+8)
                pkts.append(d[off+28:off+28+caplen])
            off += blen
        return pkts
    raise SystemExit('only pcapng supported')

def derive(pcap, rfw_path=None):
    if rfw_path is None:
        rfw_path = os.environ.get('RK260X_FW') or os.path.join(_data_fw())
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..')
    outdir = os.path.join(here, 'derived')
    os.makedirs(outdir, exist_ok=True)
    here = outdir
    pkts = read_pkts(pcap)
    cmds, writes = [], []
    devs = set(p[11] for p in pkts if len(p) >= 48)
    dev = max(devs)  # updater instance (higher addr after re-enum)
    for p in pkts:
        if len(p) < 64 or p[8] != 0x53 or p[9] != 3 or p[11] not in devs: continue
        data = p[64:]
        if len(data) >= 31 and data[:4] == b'USBC':
            cdblen = data[14]
            cmds.append([data[15:15+cdblen].hex(), None])
        elif cmds and len(data) == 2112:
            cmds[-1][1] = data.hex()
            cdb = bytes.fromhex(cmds[-1][0])
            if cdb[0] == 5:
                writes.append((int.from_bytes(cdb[2:6], 'big'), data.hex()))
    json.dump(cmds, open(os.path.join(here, 'full_stream.json'), 'w'))
    json.dump(writes, open(os.path.join(here, 'update_stream.json'), 'w'))
    print('full_stream: %d cmds, %d writes' % (len(cmds), len(writes)))
    # page template vs original .rfw
    rfw = open(rfw_path, 'rb').read()
    def match_len(a, b):
        n = 0
        for x, y in zip(a, b):
            if x != y: break
            n += 1
        return n
    pmap, expect = [], None
    for lba, hexdata in writes:
        data = bytes.fromhex(hexdata)[:2048]
        m, off = 0, -1
        if expect is not None and expect + 2048 <= len(rfw):
            m = match_len(data, rfw[expect:expect+2048]); off = expect
        if m < 2048:
            i = rfw.find(data[:16])
            if i >= 0:
                m2 = match_len(data, rfw[i:i+2048])
                if m2 > m: m, off = m2, i
        if m >= 16:
            pmap.append([off, m]); expect = (off + 2048) if m == 2048 else None
        else:
            pmap.append(None); expect = None
    json.dump(pmap, open(os.path.join(here, 'page_template.json'), 'w'))
    print('page_template: %d/%d pages sourced' % (sum(1 for p in pmap if p), len(pmap)))
    # spare (ECC) affine-map basis: full 16B group per 512B block
    groups = {}
    for lba, hexdata in writes:
        pl = bytes.fromhex(hexdata)
        for gi in range(4):
            groups.setdefault(pl[gi*512:(gi+1)*512], pl[2048+gi*16:2048+(gi+1)*16])
    def bits(d):
        v = 0
        for i, b in enumerate(d): v |= b << (8*i)
        return v
    if bytes(512) not in groups:
        raise SystemExit('capture lacks an all-zero 512B block (constant C)')
    C = groups[bytes(512)]
    samples = [(bits(d), bits(bytes(a ^ b for a, b in zip(g, C))))
               for d, g in groups.items() if set(d) != {0xff}]
    basis = {}
    for vin, vout in samples:
        while vin:
            hb = vin.bit_length() - 1
            if hb in basis:
                bin_, bout = basis[hb]
                vin ^= bin_; vout ^= bout
            else:
                basis[hb] = (vin, vout); break
    with open(os.path.join(here, 'spare_basis.bin'), 'wb') as f:
        f.write(C.to_bytes(16, 'little') if isinstance(C, int) else C)
        f.write(len(basis).to_bytes(4, 'little'))
        for hb in sorted(basis):
            vin, vout = basis[hb]
            f.write(vin.to_bytes(512, 'little'))
            f.write(vout.to_bytes(16, 'little'))
    print('spare_basis: rank %d/4096 from %d blocks' % (len(basis), len(samples)))

