# DonePlay-M3i: reverse-engineering of Explay M3i (RK2606A-based player)

Reverse-engineering and research of the firmware, so one can use it (*but why?*)
to goof around with their old (*and agonizing*) cheap music player.

This project is a playground testing the capabilities of GLM-5.3, Pi harness, and Reverse Engineer Anything.
Most of the work is done in semi-automatic mode in Pi: a meatbag (me) engages in a dialogue with a silicon 
overlord, sets tasks, and refines the output. And here is what we've got so far.



## Documentation
- [RESEARCH.md](docs/RESEARCH.md) — public writeup of the whole RE journey
- [HANDOFF.md](HANDOFF.md) — technical state & continuation notes (agent sessions)

## The device

See [Explay_M3i.md](Explay_M3i.md) for the hardware at hand: an Explay M3i
(Russian brand, OEM: Digi-in) on **RockChip RK2606A** — ZSP400 DSP core,
Samsung K9LAG08 MLC NAND (2 GB), 220x176 TFT. Flash ID on device: `ec d5 55 25 00`.

## Key protocol facts (all verified on-device)

- **Upgrade mode**: hold PLAY while plugging USB -> `071b:3202`.
  The mask-ROM downloader accepts D.img/P.img over EP0 vendor requests
  (bRequest 0x0C, wIndex 0x471/0x472, CRC-16/CCITT-FALSE chunked transfer),
  then re-enumerates as a high-speed BOT updater (same VID:PID).
- **BOT updater**: standard CBW/CSW with vendor CDBs (TUR, READ_FLASH_ID,
  SET_DEVICE_ID, TEST_BAD_BLOCK, READ_10, WRITE_10, ERASE_10, READ/WRITE_SPARE,
  RESET). `dCBWDataTransferLength` is always 0; LBA = 512B sectors (BE32 in
  CDB[2..5]); WRITE10 = one 2 KB page per command with a 2048+64-byte payload
  (data + host-computed ECC spare).
- **Firmware container (.rfw)**: XOR-encrypted blocks (one global 512-byte key,
  per-block keystream anchors); on-flash content is stored encrypted as-is.
- **UI images**: big-endian BGR565 rasters at the offsets listed in
  `data/captures/m3i.tl` (map by FirmwarePuller, verified exact).

## Recovery

The boot ROM is mask ROM - the player is effectively unbrickable. If anything
goes wrong: hold PLAY, plug in USB, then `uv run rkx flash` re-flashes the
stock firmware from the captured update stream.

## Status

- [x] ROM download protocol (D+P) - verified on-device
- [x] Updater BOT protocol incl. flash read/write/erase - verified
- [x] Full official-update replay flasher - device boots after flash
- [x] .rfw crypto (XOR key, block anchors), firmware stages extracted
- [x] NAND ECC/spare computation for arbitrary data - validated on corpus
- [x] Custom firmware pipeline (modify .rfw -> build -> flash) - **verified on-device** (boot animation frame edited, flashed, player boots normally, 2026-11-23)
- [x] UI image map + GUI editor (.tl format, verified offsets)
- [x] Original OEM toolchain recovered from old-web archives (2009 "Rockchip
  RK260X GDK" → RockTools: GCC/sdas/sdld for ZSP400) — operational under wine
  via `scripts/zsp_build.py`, validated against the shipped 2006 build
  artifacts of the SDK's Snake game (2026-11-23)
- [x] ZSP400 disassembler fixed & validated against the original LSI assembler
  (register fields are 4-bit; r8-r15 were previously mislabeled)
- [ ] ZSP code patching (spectrum analyzer height, UI behavior)
- [ ] Native-code firmware mods via the toolchain (menu injection etc.)

## rk260x-tools

Reverse-engineering and flashing toolset for **RockChip RK2606A / RK26xx**
MP3/MP4 players (LSI ZSP400 DSP core). Developed and verified on the
**Explay M3i**; applicable to other players of the same generation.

## Setup (uv — no system packages touched)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # once
uv sync                                           # creates .venv with pyusb + pillow
```

## Usage

```bash
uv run rkx --help

# Device (player in upgrade mode: hold PLAY while plugging; USB 071b:3202)
uv run rkx status                 # ROM / updater mode detection
uv run rkx info                   # boot updater, read NAND flash ID
uv run rkx flash                               # flash STOCK firmware (recovery: unbricks anything)
uv run rkx flash modified.rfw                  # flash custom firmware — stream built automatically
uv run rkx build modified.rfw out.json        # (advanced) build stream json only, for inspection

# Firmware container
uv run rkx rfw-info firmware.rfw               # header/blocks/anchors
uv run rkx rfw-extract firmware.rfw outdir/    # decrypt code stages

# Derive flasher artifacts from a usbmon capture (one-time, on any machine)
uv run rkx derive update.pcapng --rfw original.rfw

# GUI image browser/editor (needs a display)
uv run rkx gui --map m3i.tl
```

## Layout
```
src/rk260x/
  rockusb.py    USB transport: ROM D+P download + updater BOT protocol
  flasher.py    NAND flasher (replay/build) + spares via ecc.py
  ecc.py        NAND spare ECC (exact port of updater's 512B→3B Hamming
                + full 16B spare-group affine solver)
  rfw.py        .rfw container: parse, XOR decrypt, stage extraction
  zspdis.py     ZSP400 disassembler
  cli.py        `rkx` entry point
  gui/viewer.py firmware image browser/editor (.tl maps, PNG import/export,
                chunk stepping, map editing)
data/           runtime assets (XOR key, ROM-download payloads)
derived/        generated artifacts (gitignored; created by `rkx derive`)
scripts/
  zsp_build.py  build ZSP400 code with the recovered RockTools sdspI
                toolchain under wine (asm/cc/link/elf2bin; emits BE images
                + symbol maps ready for firmware patching)
  (other)       one-off analysis helpers
```

## USB access
Linux: your user needs access to the device node, e.g. udev rule
`SUBSYSTEM=="usb", ATTRS{idVendor}=="071b", ATTRS{idProduct}=="3202", MODE="0666"`.
In an Incus container, passthrough with
`incus config device add <c> player usb vendorid=071b productid=3202 uid=1000 gid=1000 mode=0666`.

## Safety
The boot ROM is in mask ROM — the player is effectively unbrickable:
hold PLAY while plugging USB and re-flash with `uv run rkx flash`.
