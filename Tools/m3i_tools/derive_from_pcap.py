#!/usr/bin/env python3
"""Regenerate the derived flasher artifacts from the usbmon capture:
  full_stream.json   - all rockusb CBWs + payloads (verbatim replay source)
  update_stream.json - write pages only (legacy)
  page_template.json - per-page .rfw source map (for flash.py build)
  protocol_trace.txt - human-readable trace
Usage: python3 derive_from_pcap.py <capture.pcapng|pcap> [original.rfw]
Expects the XOR key at ./xor_key_512.bin (committed).
"""
import json, os, struct, sys

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

def main():
    pcap = sys.argv[1]
    rfw_path = sys.argv[2] if len(sys.argv) > 2 else '/data/ReverseEngineering/ExplayM3i/Firmware/Firmware M3i 070930.rfw'
    here = os.path.dirname(os.path.abspath(__file__))
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

if __name__ == '__main__':
    main()
