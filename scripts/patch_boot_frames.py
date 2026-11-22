#!/usr/bin/env python3
"""patch_boot_frames.py — set the boot animation frame count.

The boot-animation loop (DisplayPowerOnFlash) in the main firmware loads its
frame count-1 into r0 at .rfw offset 0x3168 (plaintext `movl r0, N-1`,
big-endian word). The loop displays frames 0..N-1 (frame i at flash image
offset i*77440). Default in stock M3i firmware: 12 frames (value 11).

Usage:
  python3 patch_boot_frames.py <in.rfw> <out.rfw> <frames> [boot|shutdown]
Example: show only the first boot-animation frame:
  python3 patch_boot_frames.py stock.rfw mod.rfw 1 boot
"""
import sys

# .rfw offsets of the frame-count instructions (`movl rX, N-1`):
BOOT_OFF = 0xF3F4          # power-ON animation (DisplayPowerOnFlash), stock: 23 -> 24 frames
SHUTDOWN_OFF = 0x3168      # power-OFF animation (DisplayPowerOffFlash), stock: 11 -> 12 frames
KEY = '/data/ReverseEngineering/ExplayM3i/data/xor_key_512.bin'
ANCHOR = 172               # main-fw block keystream anchor


def main():
    src, dst, frames = sys.argv[1], sys.argv[2], int(sys.argv[3])
    which = sys.argv[4] if len(sys.argv) > 4 else 'boot'
    OFF_WORD = BOOT_OFF if which == 'boot' else SHUTDOWN_OFF
    if not 1 <= frames <= 255 + 1:
        raise SystemExit('frames must be 1..256')
    val = frames - 1
    k = open(KEY, 'rb').read()
    fw = bytearray(open(src, 'rb').read())
    # verify current plaintext word == 20 xx (movl r0, imm)
    def dec(off):
        return fw[off] ^ k[(off - ANCHOR) % 512]
    cur = (dec(OFF_WORD) << 8) | dec(OFF_WORD + 1)
    if (cur >> 8) & 0xF8 != 0x20:
        raise SystemExit(f'unexpected instruction at {OFF_WORD:#x}: {cur:04x} (want movl rX,#imm) — aborting')
    print(f'current frame count-1 = {cur & 0xFF} ({(cur & 0xFF) + 1} frames)')
    # patch low byte (offset OFF_WORD+1); encryption is a plain XOR stream,
    # so new_enc = old_enc ^ old_plain ^ new_plain
    old_plain = cur & 0xFF
    fw[OFF_WORD + 1] ^= old_plain ^ val
    open(dst, 'wb').write(bytes(fw))
    print(f'patched to {frames} frames -> {dst}')
    print('flash with: uv run rkx flash %s' % dst)


if __name__ == '__main__':
    main()
