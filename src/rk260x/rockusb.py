#!/usr/bin/env python3
"""
rockusb.py — Talk to RockChip RK260x players in USB upgrade ("RockUSB") mode.

Protocol (reverse-engineered from rockusb.sys + Consumer.exe, verified on-device):
  1. Boot-ROM download mode (hold PLAY while plugging; PID 071b:3202):
     EP0 vendor control requests: bmRequestType 0x40/0xC0, bRequest 0x0C,
     wValue=0, wIndex=CMD, wLength=len(data):
       0x471 = download D.img (FW USB descriptor table), 256B chunks + CRC16 BE
       0x472 = download P.img (updater code),        256B chunks + CRC16 BE
     Chunking (FUN_00412470): whole payload = data + crc16_ccitt_false(data)
     big-endian; sent in 256B chunks, last partial chunk carries the CRC;
     if (size<256: single send, pad 1 byte when size%64==0)
     if (size>=256 and (size+2)%64==0): one extra 1-byte 0x00 send.
     On success the ROM re-enumerates running the downloaded updater
     (USB 2.0 HS, same VID:PID, 512B bulk endpoints).
  2. Updater mode: SCSI Bulk-Only Transport with RockChip vendor CDBs
     (FW_Upgrade.h opcodes; CBW/CDB layout from Consumer.exe FUN_00410a00):
       opcode 0x00 TEST_UNIT_READY   CDBlen 6
       opcode 0x01 READ_FLASH_ID     CDBlen 6   IN  (NAND ID bytes)
       opcode 0x02 SET_DEVICE_ID     CDBlen 6
       opcode 0x03 TEST_BAD_BLOCK    CDBlen 10  IN
       opcode 0x04 READ_10           CDBlen 10  IN  CDB[2:6]=LBA BE32, CDB[7:9]=n BE16
       opcode 0x05 WRITE_10          CDBlen 10  OUT same layout
       opcode 0x06 ERASE_10          CDBlen 10
       opcode 0x07 WRITE_SPARE       CDBlen 16
       opcode 0x08 READ_SPARE        CDBlen 16  IN
       opcode 0xFF RESET             CDBlen 6
     Block size = 512 bytes (count<<9 data bytes).

Usage:
  python3 rockusb.py status              — find device, show mode
  python3 rockusb.py boot                — D.img+P.img download (enter updater)
  python3 rockusb.py id                  — read flash ID (updater mode)
  python3 rockusb.py pull <out.bin> [blocks] [first_block]
                                          — dump flash (default 20480 blocks = 10MB)
  python3 rockusb.py push <image.bin> <first_block> — REFlash flash (DANGER!)

Requires pyusb. Run as user with access to the USB device node.
"""

import os
import struct
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_DATA = os.path.join(_HERE, '..', '..', 'data')
ROM_D_IMG = os.path.join(_DATA, 'RockUpdateD.img')
ROM_P_IMG = os.path.join(_DATA, 'RockUpdateP.img')

VID = 0x071B
PID = 0x3202

# --- ROM download protocol ----------------------------------------------------
ROM_REQUEST = 0x0C           # bRequest
ROM_CMD_D = 0x0471           # wIndex: D.img (descriptors)
ROM_CMD_P = 0x0472           # wIndex: P.img (updater code)

# --- Vendor opcodes (FW_Upgrade.h) ---------------------------------------------
OP_TUR = 0x00
OP_READ_FLASH_ID = 0x01
OP_SET_DEVICE_ID = 0x02
OP_TEST_BAD_BLOCK = 0x03
OP_READ_10 = 0x04
OP_WRITE_10 = 0x05
OP_ERASE_10 = 0x06
OP_WRITE_SPARE = 0x07
OP_READ_SPARE = 0x08
OP_RESET = 0xFF

CSW_GOOD, CSW_FAIL, CSW_PHASE = 0x00, 0x01, 0x02
BLK = 512
CHUNK = 0x100


def crc16_ccitt_false(data: bytes, crc: int = 0xFFFF) -> int:
    """CRC-16/CCITT-FALSE — identical to Consumer.exe FUN_00408400."""
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


class RockError(Exception):
    pass


def find_device():
    import usb.core
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        raise RockError("no RockUSB device (071b:3202) — hold PLAY while plugging")
    return dev


def device_mode(dev):
    """ROM mode: EP0 maxpacket 64, USB 1.1. Updater: 512, HS."""
    try:
        return "updater" if dev.get_active_configuration()[(0, 0)][0].wMaxPacketSize == 512 else "rom"
    except Exception:
        return "rom"


class RockUsb:
    def __init__(self):
        self.dev = find_device()
        self.dev.set_configuration()
        self.ep_out = self.ep_in = None
        cfg = self.dev.get_active_configuration()
        intf = cfg[(0, 0)]
        for ep in intf:
            if ep.bEndpointAddress & 0x80:
                self.ep_in = ep.bEndpointAddress
            else:
                self.ep_out = ep.bEndpointAddress
        self.tag = 1

    # -- ROM download ----------------------------------------------------------
    def rom_out(self, cmd, data):
        return self.dev.ctrl_transfer(0x40, ROM_REQUEST, 0, cmd, data, 6000)

    def rom_download(self, blob, cmd):
        """Stream a file exactly like Consumer.exe FUN_00412470."""
        crc = crc16_ccitt_false(blob)
        size = len(blob)
        if size < CHUNK:
            self.rom_out(cmd, blob + bytes([crc >> 8, crc & 0xFF]))
            if size % 0x40 == 0:
                self.rom_out(cmd, b"\0")
        else:
            for i in range(size >> 8):
                self.rom_out(cmd, blob[i * CHUNK:(i + 1) * CHUNK])
            rem = size & 0xFF
            last = (blob[(size >> 8) * CHUNK:] if rem else b"") + bytes([crc >> 8, crc & 0xFF])
            self.rom_out(cmd, last)
            if (size + 2) % 0x40 == 0:
                self.rom_out(cmd, b"\0")

    def boot_updater(self, d_img, p_img):
        """D.img + P.img download; wait for the updater to re-enumerate."""
        print("mode:", device_mode(self.dev))
        if device_mode(self.dev) == "updater":
            print("already in updater mode")
            return
        print("downloading D.img (%d B)..." % len(d_img))
        self.rom_download(d_img, ROM_CMD_D)
        print("downloading P.img (%d B)..." % len(p_img))
        self.rom_download(p_img, ROM_CMD_P)
        print("waiting for re-enumeration...")
        t0 = time.time()
        while time.time() - t0 < 60:
            time.sleep(0.3)
            try:
                if find_device() is None:
                    break
            except Exception:
                break
        time.sleep(1.0)
        self.dev = find_device()
        self.dev.set_configuration()
        cfg = self.dev.get_active_configuration()
        intf = cfg[(0, 0)]
        for ep in intf:
            if ep.bEndpointAddress & 0x80:
                self.ep_in = ep.bEndpointAddress
            else:
                self.ep_out = ep.bEndpointAddress
        print("re-enumerated; mode:", device_mode(self.dev))

    # -- BOT vendor transport ----------------------------------------------------
    def _cbw_raw(self, raw_cbw, out):
        """Send raw 31-byte CBW (dlen already inside)."""
        self.dev.write(self.ep_out, raw_cbw)

    def _cbw(self, cdb, dlen, out):
        b = b"USBC" + struct.pack("<II", self.tag, dlen)
        b += bytes([0x00 if out else 0x80, 0, len(cdb)]) + cdb
        b += b"\0" * (31 - len(b))
        self.tag += 1
        self.dev.write(self.ep_out, b)

    def _csw(self):
        csw = bytes(self.dev.read(self.ep_in, 13, timeout=5000))
        if csw[:4] != b"USBS":
            raise RockError("bad CSW: %r" % csw)
        return csw[12]

    def vendor(self, opcode, dlen=0, out=False, cdb_extra=b"", cdblen=None):
        if cdblen is None:
            cdblen = 16 if opcode in (OP_WRITE_SPARE, OP_READ_SPARE) else (10 if opcode in (OP_TEST_BAD_BLOCK, OP_READ_10, OP_WRITE_10, OP_ERASE_10) else 6)
        cdb = bytes([opcode]) + cdb_extra
        cdb = cdb[:cdblen] + b"\0" * max(0, cdblen - len(cdb))
        self._cbw(cdb, dlen, out)
        data = b""
        if dlen and not out:
            data = bytes(self.dev.read(self.ep_in, dlen, timeout=10000))
        status = self._csw()
        if status != CSW_GOOD:
            raise RockError("CSW status %d for opcode %#x" % (status, opcode))
        return data

    # -- vendor commands ----------------------------------------------------------
    def test_unit_ready(self):
        self.vendor(OP_TUR)

    def read_flash_id(self):
        return self.vendor(OP_READ_FLASH_ID, 8)

    def test_bad_block(self, block):
        return self.vendor(OP_TEST_BAD_BLOCK, cdb_extra=struct.pack(">I", block) + b"\0" * 5, cdblen=10)

    def read_10(self, lba, count):
        cdb_extra = struct.pack(">I", lba) + b"\0" + struct.pack(">H", count) + b"\0"
        data = b""
        todo = count
        got = 0
        while todo > 0:
            n = min(todo, 64)  # 32KB max per request (updater buffer)
            if n < todo and n != 64:
                n = 64 if todo > 64 else todo
            chunk = self.vendor(OP_READ_10, n * BLK, cdb_extra=struct.pack(">I", lba + got) + b"\0" + struct.pack(">H", n) + b"\0", cdblen=10)
            data += chunk
            got += n
            todo -= n
        return data

    def write_10(self, lba, data):
        off = 0
        while off < len(data):
            n = min(64, (len(data) - off) // BLK)
            if n == 0:
                break
            cdb_extra = struct.pack(">I", lba + off // BLK) + b"\0" + struct.pack(">H", n) + b"\0"
            self._cbw(bytes([OP_WRITE_10]) + cdb_extra + b"\0" * max(0, 10 - 1 - len(cdb_extra))[:10 - 1 - len(cdb_extra)], n * BLK, out=True)
            self.dev.write(self.ep_out, data[off:off + n * BLK])
            st = self._csw()
            if st != CSW_GOOD:
                raise RockError("WRITE_10 status %d" % st)
            off += n * BLK

    def erase_10(self, block):
        self.vendor(OP_ERASE_10, cdb_extra=struct.pack(">I", block) + b"\0" * 5, cdblen=10)

    def read_spare(self, block):
        return self.vendor(OP_READ_SPARE, cdb_extra=struct.pack(">I", block), cdblen=16)

    def reset(self):
        self.vendor(OP_RESET)


def cmd_status():
    try:
        dev = find_device()
    except RockError as e:
        print(e)
        return 1
    print("found 071b:3202, mode:", device_mode(dev))
    return 0


def cmd_boot():
    import os
    rock = RockUsb()
    here = os.path.dirname(os.path.abspath(__file__))
    d = open(os.path.join(here, "RockUpdateD.img"), "rb").read()
    p = open(os.path.join(here, "RockUpdateP.img"), "rb").read()
    rock.boot_updater(d, p)
    rock.test_unit_ready()
    print("flash ID:", rock.read_flash_id().hex())
    return 0


def cmd_pull(out, blocks=20480, first=0):
    rock = RockUsb()
    if device_mode(rock.dev) == "rom":
        print("in ROM mode; boot updater first (boot command) or use full flow")
        return 1
    print("flash ID:", rock.read_flash_id().hex())
    with open(out, "wb") as f:
        for i in range(first, first + blocks, 64):
            n = min(64, first + blocks - i)
            data = rock.read_10(i, n)
            f.write(data)
            done = (i + n - first) * BLK
            total = blocks * BLK
            print("\r%d/%d bytes" % (done, total), end="", flush=True)
    print("\npulled %d blocks to %s" % (blocks, out))
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == "status":
        return cmd_status()
    if cmd == "boot":
        return cmd_boot()
    if cmd == "pull":
        out = sys.argv[2]
        blocks = int(sys.argv[3]) if len(sys.argv) > 3 else 20480
        first = int(sys.argv[4]) if len(sys.argv) > 4 else 0
        return cmd_pull(out, blocks, first)
    if cmd == "id":
        rock = RockUsb()
        print("flash ID:", rock.read_flash_id().hex())
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main())

def boot_default_images(r=None):
    """Convenience: download the bundled D.img/P.img (in data/) and return a
    live RockUsb session with the updater running."""
    import time as _t
    r = r or RockUsb()
    if device_mode(r.dev) == 'rom':
        r.boot_updater(open(ROM_D_IMG, 'rb').read(), open(ROM_P_IMG, 'rb').read())
        _t.sleep(0.8)
        r = RockUsb()
    return r
