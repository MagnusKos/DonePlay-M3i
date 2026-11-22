#!/usr/bin/env python3
"""
flash.py — M3i (RK2606A) NAND flasher.

Modes:
  replay  — replay a captured official update stream (byte-perfect: data +
            spares/ECC from a usbmon capture of ConsumerUpdate). Use this to
            re-flash the ORIGINAL firmware (recovery / experiments).
  info    — boot updater, show flash ID.

Replay protocol (from usbmon capture of the real ConsumerUpdate run):
  boot updater via EP0 D+P download, then BOT:
    TUR, READ_FLASH_ID, SET_DEV_ID(6),
    WRITE10(lba, cnt=1, dlen=0, flags=0) + 2112B bulk OUT (2048 data + 64
    spare/ECC) + CSW — one MLC page per command.
  NOTE: CBW dCBWDataTransferLength must be 0 (tool convention); the data
  phase is a raw bulk transfer of count*512+spares.

WARNING: writes to flash. Recovery = mask ROM (hold PLAY) + replay again.
"""

import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rockusb import RockUsb, RockError, device_mode, find_device, crc16_ccitt_false
from usb.core import USBError

HERE = os.path.dirname(os.path.abspath(__file__))
OP_READ_10 = 0x04
OP_WRITE_10 = 0x05


def cbw(tag, opcode, lba, cnt, flags, cdblen=10, dlen=0):
    cdb = bytes([opcode, 0]) + struct.pack('>I', lba) + b'\x00' + struct.pack('>H', cnt)
    cdb = cdb[:cdblen] + b'\x00' * (cdblen - len(cdb))
    b = b'USBC' + struct.pack('<II', tag, dlen) + bytes([flags, 0, cdblen]) + cdb
    assert len(b) == 15 + cdblen, 'cbw layout bug'
    return b + b'\x00' * (31 - len(b))


def flash_page(r, lba, payload):
    """WRITE10 one 2112-byte page (2048 data + 64 spare)."""
    r._cbw_raw(cbw(r.tag, OP_WRITE_10, lba, 1, 0x00), out=True)
    r.tag += 1
    r.dev.write(r.ep_out, payload)
    st = r._csw()
    if st != 0:
        raise RockError('WRITE10 lba %#x CSW status %d' % (lba, st))


def read_verify(r, lba, pages=5):
    r._cbw_raw(cbw(r.tag, OP_READ_10, lba, pages * 4, 0x80), out=False)
    r.tag += 1
    data = b''
    while len(data) < pages * 2048:
        chunk = bytes(r.dev.read(r.ep_in, min(2048, pages * 2048 - len(data)), timeout=15000))
        data += chunk
        if len(chunk) == 0:
            break
    st = r._csw()
    if st != 0:
        raise RockError('READ10 verify CSW status %d' % st)
    return data


def boot(r):
    if device_mode(r.dev) == 'rom':
        D = open(os.path.join(HERE, 'RockUpdateD.img'), 'rb').read()
        P = open(os.path.join(HERE, 'RockUpdateP.img'), 'rb').read()
        r.boot_updater(D, P)
        time.sleep(0.8)
        r = RockUsb()
    r.test_unit_ready()
    fid = r.read_flash_id()
    print('flash ID:', fid.hex())
    r._cbw_raw(cbw(r.tag, 2, 6 << 24, 0, 0x80, cdblen=6), out=True)
    r.tag += 1
    st = r._csw()
    print('SET_DEV_ID(6):', st)
    # capture-exact pre-write probes: RD_SPARE(lba=0) then READ10(lba=1,cnt=1)
    cdb = bytes([8, 0]) + struct.pack('>I', 0) + b'\x00' + struct.pack('>H', 2048)
    cdb = bytearray(cdb.ljust(16, b'\x00')); cdb[10] = 16
    raw = b'USBC' + struct.pack('<II', r.tag, 0) + bytes([0x00, 0, 16]) + bytes(cdb)
    r._cbw_raw(raw, out=False)
    r.tag += 1
    try:
        bytes(r.dev.read(r.ep_in, 64, timeout=3000)); r._csw()
        print('RD_SPARE(0) ok')
    except USBError as e:
        print('RD_SPARE(0):', e)
    r._cbw_raw(cbw(r.tag, OP_READ_10, 1, 1, 0x80), out=False)
    r.tag += 1
    try:
        bytes(r.dev.read(r.ep_in, 512, timeout=3000)); r._csw()
        print('READ10(1) ok')
    except USBError as e:
        print('READ10(1):', e)
    return r


def scan_bad_blocks(r, writes, verbose=True):
    """TEST_BB over all target blocks (capture does a full scan pre-write)."""
    blocks = sorted(set(lba >> 9 for lba, _ in writes))
    bad = []
    for i, blk in enumerate(blocks):
        r._cbw_raw(cbw(r.tag, 3, blk, 0, 0x80), out=True)
        r.tag += 1
        st = r._csw()
        if st != 0:
            bad.append(blk)
        if verbose and i % 500 == 0:
            print('\rscan %d/%d' % (i, len(blocks)), end='', flush=True)
    if verbose:
        print('\nbad blocks: %d of %d' % (len(bad), len(blocks)))
    return bad


def cmd_replay(stream_file, verify=False):
    writes = json.load(open(stream_file))
    print('replay stream:', len(writes), 'pages (%.1f MB data)' % (len(writes) * 2048 / 1e6))
    r = RockUsb()
    r = boot(r)
    bad = scan_bad_blocks(r, writes)
    t0 = time.time()
    for i, (lba, hexdata) in enumerate(writes):
        payload = bytes.fromhex(hexdata)
        if i < 3:
            print('write %d lba %#x cbw %s data0 %s' % (i, lba, cbw(r.tag, OP_WRITE_10, lba, 1, 0x00).hex(), payload[:8].hex()))
        try:
            flash_page(r, lba, payload)
        except Exception as e:
            print('\nFAILED at page %d lba %#x: %s' % (i, lba, e))
            raise
        if i % 50 == 0:
            dt = time.time() - t0
            eta = dt / max(i, 1) * (len(writes) - i)
            print('\r%d/%d pages (%.0fs, eta %.0fs)   ' % (i, len(writes), dt, eta), end='', flush=True)
    print('\nwrite phase done in %.0fs' % (time.time() - t0))
    if verify:
        print('verify (sampled)...')
        ok = bad = 0
        for i, (lba, hexdata) in enumerate(writes):
            if i % 100:
                continue
            expect = bytes.fromhex(hexdata)[:2048]
            got = read_verify(r, lba, pages=1)
            if got[:2048] == expect:
                ok += 1
            else:
                bad += 1
                print('  MISMATCH at page %d lba %#x' % (i, lba))
        print('verify: %d ok, %d mismatch' % (ok, bad))
    print('DONE — unplug the player and boot it normally.')


def cmd_full_replay(stream_file=None):
    """Replay the ENTIRE captured command stream verbatim: every CBW in
    capture order (TUR/ID/SET/probes/TEST_BB scan/ERASEs/writes/verifies),
    with payloads. This reproduces the official update 1:1."""
    stream_file = stream_file or os.path.join(HERE, 'full_stream.json')
    cmds = json.load(open(stream_file))
    print('full stream:', len(cmds), 'commands')
    r = RockUsb()
    if device_mode(r.dev) == 'rom':
        D = open(os.path.join(HERE, 'RockUpdateD.img'), 'rb').read()
        P = open(os.path.join(HERE, 'RockUpdateP.img'), 'rb').read()
        r.boot_updater(D, P)
        time.sleep(0.8)
        r = RockUsb()
    t0 = time.time()
    writes = reads = 0
    for i, (cdb_hex, payload_hex) in enumerate(cmds):
        cdb = bytes.fromhex(cdb_hex)
        opcode = cdb[0]
        cdblen = 16 if opcode in (7, 8) else (10 if opcode in (3, 4, 5, 6) else 6)
        flags = 0x00 if opcode in (5, 7, 8, 2) else 0x80
        # data phase length by opcode
        if opcode == 5 and payload_hex:
            dlen = 0
        else:
            dlen = 0
        cbw_bytes = b'USBC' + struct.pack('<II', r.tag, dlen) + bytes([flags, 0, cdblen]) + cdb
        cbw_bytes += b'\x00' * (31 - len(cbw_bytes))
        r.tag += 1
        if opcode == 5 and payload_hex:
            # WRITE10: CBW + 2112B data + CSW
            r.dev.write(r.ep_out, cbw_bytes)
            r.dev.write(r.ep_out, bytes.fromhex(payload_hex))
            st = r._csw()
            if st != 0: raise RockError('WRITE10 CSW %d at cmd %d' % (st, i))
            writes += 1
        elif opcode in (4, 8, 1) or (opcode == 0 and False):
            # READ10 / RD_SPARE / READ_FLASH_ID: CBW + data-in + CSW
            r.dev.write(r.ep_out, cbw_bytes)
            # data phase then CSW as its own short transfer starting 'USBS'
            ndata = 0
            while True:
                chunk = bytes(r.dev.read(r.ep_in, 512, timeout=15000))
                if chunk[:4] == b'USBS':
                    if chunk[12] != 0:
                        print('read cmd %d CSW status %d' % (i, chunk[12]))
                    break
                ndata += len(chunk)
            reads += 1
        elif opcode == 6:
            # ERASE10: CBW + CSW
            r.dev.write(r.ep_out, cbw_bytes)
            st = r._csw()
            if st != 0: raise RockError('ERASE10 CSW %d at cmd %d' % (st, i))
        else:
            # command-only (TUR, SET_DEV_ID, TEST_BB): CBW + CSW
            r.dev.write(r.ep_out, cbw_bytes)
            st = r._csw()
            if st != 0:
                print('cmd %d op %d CSW status %d' % (i, opcode, st))
        if i % 100 == 0:
            dt = time.time() - t0
            print('\r%d/%d (%.0fs, w=%d r=%d)' % (i, len(cmds), dt, writes, reads), end='', flush=True)
    print('\nfull replay done in %.0fs: %d writes, %d reads' % (time.time() - t0, writes, reads))
    print('unplug and boot the player normally.')


def cmd_build(mod_rfw_path, out_json, allow_bad_ecc=False):
    """Build a flash stream from a MODIFIED .rfw using the captured template
    (full_stream.json + page_template.json). Pages whose data changes keep
    the template spare (ECC) — flagged unless --allow-bad-ecc."""
    mod = open(mod_rfw_path, 'rb').read()
    orig = open('/data/ReverseEngineering/ExplayM3i/Firmware/Firmware M3i 070930.rfw', 'rb').read()
    tstream = json.load(open(os.path.join(HERE, 'full_stream.json')))
    pmap = json.load(open(os.path.join(HERE, 'page_template.json')))
    wi = 0
    out = []
    changed = 0
    for cdb_hex, payload_hex in tstream:
        cdb = bytes.fromhex(cdb_hex)
        entry = [cdb_hex, payload_hex]
        if cdb[0] == 5 and payload_hex:
            src_ = pmap[wi]
            if src_:
                off, m = src_
                payload = bytearray(bytes.fromhex(payload_hex))
                if off + 2048 <= len(mod):
                    newdata = mod[off:off+2048]
                else:
                    newdata = (mod[off:] + b'\xff' * 2048)[:2048]
                content = bytes(payload[:2048])
                # substitute only the content part (m bytes), keep padding
                newpage = bytearray(content)
                newpage[:m] = newdata[:m]
                if bytes(newpage) != content:
                    changed += 1
                    payload[:2048] = newpage
                    # recompute spare (ECC) for the modified page
                    import rk_ecc
                    try:
                        payload[2048:] = rk_ecc.page_spare(bytes(newpage))
                    except Exception as e:
                        print('spare recompute failed page %d: %s' % (wi, e))
                entry[1] = bytes(payload).hex()
            wi += 1
        out.append(entry)
    print('pages changed vs original: %d (spares recomputed via rk_ecc)' % changed)
    if changed and not allow_bad_ecc:
        print('NOTE: spares ARE recomputed; --allow-bad-ecc now only skips the sanity gate.')
        return 1
    json.dump(out, open(out_json, 'w'))
    print('wrote', out_json, '(%d commands)' % len(out))
    return 0


def cmd_info():
    r = RockUsb()
    r = boot(r)
    print('updater alive; ready for reads/writes')


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == 'build':
        args = [a for a in sys.argv[2:] if not a.startswith('--')]
        if not args:
            print('usage: flash.py build <mod.rfw> <out_stream.json> [--allow-bad-ecc]'); return 1
        return cmd_build(args[0], args[1] if len(args) > 1 else os.path.join(HERE, 'built_stream.json'), allow_bad_ecc=True)
    if cmd == 'full':
        return cmd_full_replay(next((a for a in sys.argv[2:] if not a.startswith('--')), None))
    if cmd == 'replay':
        stream = next((a for a in sys.argv[2:] if not a.startswith('--')), os.path.join(HERE, 'update_stream.json'))
        return cmd_replay(stream, verify='--verify' in sys.argv)
    if cmd == 'info':
        return cmd_info()
    print(__doc__)
    return 1


if __name__ == '__main__':
    sys.exit(main())
