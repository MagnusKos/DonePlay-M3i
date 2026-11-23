# Hacking the Explay M3i (RockChip RK2606A) — research writeup

A chronicle of reverse-engineering a 2007 Russian-brand MP3 player down to
custom firmware, using an AI agent (GLM via the pi.dev harness + REA/Ghidra).
Everything below was verified on real hardware.

## The target

**Explay M3i**: 1 GB MP3/MP4 player, 220×176 TFT, Russian brand, OEM by
Digi-in. SoC: **RockChip RK2606A** — not an ARM chip, but an **LSI ZSP400
DSP** core (16-bit words, big-endian, 256 KB IRAM). NAND: Samsung K9LAG08
(2 GB MLC). USB VID 071b:3202 (boot/upgrade mode), 071b:3203 (normal mode).

## Entry points

1. **Original Windows tools** (ConsumerUpdate/Consumer.exe, rockusb.sys,
   FirmwarePuller.exe) — reversed with Ghidra 12.2 via the REA agent toolkit.
2. **The SDK**: `solderneer/SimpleMP4` on GitHub contains the original
   RockChip RK26xx SDK C source (USB stack, menus, codecs) — the M3i firmware
   is a customization of the same SDK. This was the Rosetta stone.
3. **The firmware file** (`Firmware M3i 070930.rfw`, 9.9 MB) and a
   **usbmon capture** of a real update session (taken on Linux while the
   original updater ran in VirtualBox/XP).
4. **The original OEM toolchain** (see "The original toolchain" below):
   the LSI `sdspI` C compiler, assembler and linker for ZSP400.

## Findings

### Firmware container (.rfw)
- Header `ROCK260x2005VER5.00` + date, then **blocks XOR-encrypted with one
  global 512-byte key**; the keystream phase restarts at each block
  ("anchor"). Key recovered by a many-time-pad attack on encrypted
  zero-pages; anchors found via ZSP vector-table signatures
  (`reti`+`nop` padding) or entropy scoring.
- The flash stores the encrypted bytes as-is — the device decrypts at load.

### USB protocols (both reversed and verified on-device)
- **ROM download mode** (hold PLAY at plug-in): EP0 vendor requests
  (bRequest 0x0C, wIndex 0x471/0x472) stream D.img/P.img with
  CRC-16/CCITT-FALSE chunking; the ROM then boots the downloaded updater.
- **Updater**: SCSI Bulk-Only Transport with vendor CDBs (TUR, READ_FLASH_ID,
  SET_DEVICE_ID, TEST_BAD_BLOCK, READ_10, WRITE_10, ERASE_10, READ/WRITE_SPARE).
  Quirks: `dCBWDataTransferLength` always 0; WRITE10 = one 2 KB NAND page per
  command with 2048+64 B payload (data + host-computed ECC spare); ~30-60 s
  idle timeout; the mask ROM makes the device effectively unbrickable.

### NAND ECC
- Exact port of the updater's 512 B → 3 B Hamming ECC (from Consumer.exe
  `FUN_00408460`), plus the full 16-byte spare group solved as a GF(2)
  affine map (rank 4096/4096 from the capture corpus) — spares can be
  computed for arbitrary data, enabling custom firmware.

### ZSP400 tooling
- Wrote a disassembler from the official LSI ZSP400 manual (found online):
  `src/rk260x/zspdis.py`.
- **Bug found & fixed with the help of the original assembler**: register
  fields are 4-bit, not 3 — r8–r15 were silently mislabeled as r0–r7 in ~43%
  of the firmware disassembly. Validated by round-tripping assembler output
  through `zspdis` (100% match).
- The original assembler/compiler/linker run under wine via
  `scripts/zsp_build.py` (asm/cc/link/elf2bin; emits big-endian images +
  symbol maps ready to patch into the .rfw).

### UI resources
- Images: big-endian BGR565 rasters at fixed offsets (map in
  `data/captures/m3i.json`, verified exact); boot animation = 24 frames of
  ПРИВЕТ growing; strings: UTF-16LE, 64-byte slots, language packs 0x5000
  apart.

### Code patches (verified on-device)
- Boot/shutdown animation frame counts are single ZSP instructions
  (`movl rN, count-1`) at firmware offsets 0xF3F4 / 0x3168 — patched to
  show 1 frame: `scripts/patch_boot_frames.py`.

## The original toolchain

Hand-assembling ZSP400 patches was painful, so we went looking for the
original SDK. It eventually turned up in old community archives of the
2006–2009 player-hacking scene, complete with the OEM firmware tools:

- **RockCompiler `sdspI`**: GCC-derived `sdcc`/`sdcc1`/`sdcpp`, `sdas`,
  `sdld`, `sdar` for ZSP400 (LSI, 2005) — this is what the M3i firmware
  itself was built with.
- Caveats that matter when using it:
  - object/executable files are ELF, machine `EM_ZSP` (0x4F), with section
    data stored **word-byteswapped** — the firmware image is
    `byteswap(.text)`;
  - the ELF `.text` vma is runtime address + 0x9000 (linker convention);
  - builds use `-O0` (the optimizer pass of the suite is not usable —
    its vendor license has long expired); unoptimized output is fine for
    firmware patching.
- `scripts/zsp_build.py` wraps all of this: one command produces a
  big-endian image plus a symbol map ready to be patched into the `.rfw`.

Provenance details are kept in the private session notes.

## Image mapping (AutoMapper, in progress)

Manual mapping (the FirmwarePuller tune-by-eye method) produced 79 entries.
We automated it by going to the source of truth: the firmware's own draw
calls. Method, all implemented in `rkx automap`:

- The UI code is not in one block — it lives in ~52 encrypted overlay
  modules scattered through the container; they are found by scoring every
  512-byte page under all 512 keystream rotations for code-likeness.
- The firmware's `DisplayPicture` twin (runtime 0x1996) is called 185
  times across those modules. A small backward slicer recovers
  `(width, height, address)` per call site: width is an immediate in r6,
  height is a pushed constant, the 32-bit flash address is built in an
  even register pair (base constant + runtime index arithmetic).
- The flash layout differs from the file order (the updater distributes
  regions), so logic addresses are translated through the flasher's own
  placement data. Images themselves are headerless BE-BGR565 rasters,
  stored exact-fit adjacent — no tables anywhere; every reference is
  computed in code.
- Findings are validated against the hand-made map, then verified by a
  human: a chess-labeled contact sheet (one label per image) lets the
  operator approve/correct each entry in a single glance.

Result so far on the M3i: 119 mapped images (was 79), including the
lock/unlock screen run, the battery/volume/play-mode icon families and a
hidden list-screen. Remaining: draws whose parameters are computed at
runtime need real per-function dataflow, and the text/font drawing path
is still unexplored.

## Toolchain (`rkx`)

```
uv run rkx status          # detect player
uv run rkx flash           # flash stock (recovery) / custom .rfw
uv run rkx build X.rfw out # build flash stream (auto ECC)
uv run rkx gui             # image browser/editor (JSON maps, PNG import)
uv run rkx rfw-info ...    # container analysis
```

Custom firmware = edit images/bytes → `rkx build` → `rkx flash` (~7 s).

## Open research

Menu injection (adding a settings item — string packs and one menu table
mapped, the live SetMenu array still to find), spectrum-analyzer height fix,
the .rfw 0x38 config-block cipher, encrypted SDK libraries.

See `HANDOFF.md` for the full technical state.
