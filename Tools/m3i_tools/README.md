# m3i_tools — Python tools for the Explay M3i (RockChip RK2606A)

Reverse-engineered with REA + Ghidra 12.2 from the original Windows tools
(Consumer.exe, rockusb.sys, FirmwarePuller) + cryptanalysis of the firmware
container + a usbmon capture of a real update. Full notes:
`../../REA-Session/NOTES.md` (private repo).

## Quick start
```bash
# GUI image browser/editor (needs display + pillow):
python3 m3i_gui.py

# Device tools (player in upgrade mode: hold PLAY while plugging; 071b:3202):
python3 rockusb.py status        # detect ROM vs updater mode
python3 flash.py info            # boot updater, show flash ID

# Custom firmware workflow:
#   1. edit images in m3i_gui.py, save modified.rfw
python3 flash.py build modified.rfw built_stream.json
python3 flash.py full            # replays the official update flow verbatim
                                # (with your image bytes + recomputed ECC spares)

# Firmware container analysis:
python3 rfw.py info "../../Firmware/Firmware M3i 070930.rfw"
python3 rfw.py extract "../../Firmware/Firmware M3i 070930.rfw" /tmp/out
```

## Files
| file | purpose |
|---|---|
| `m3i_gui.py` | GUI firmware image editor: browse/search .tl maps, custom resolution/offset viewer with chunk stepping, map editing + .tl export, PNG import/export, one-click build/flash/info tools |
| `flash.py` | NAND flasher: `full` (verbatim replay of captured official update stream — **recovery tool**, player unbrickable via mask ROM), `build` (stream from modified .rfw with auto-recomputed spares), `replay` (legacy write-only, DO NOT USE — omits erases) |
| `rockusb.py` | USB transport: ROM D+P download (EP0 vendor 0x0C, wIndex 0x471/0x472, CRC16-CCITT chunking) + updater BOT protocol (TUR/READ_FLASH_ID/SET_DEVICE_ID/READ_10/WRITE_10/ERASE_10/SPARE ops) |
| `rfw.py` | .rfw container: header parse, XOR-key block decryption, code-stage extraction |
| `rk_ecc.py` | NAND spare ECC: exact port of Consumer.exe FUN_00408460 (512B→3B Hamming) + full 16B spare-group solver (GF(2) affine map, `spare_basis.bin`) |
| `zspdis.py` | ZSP400 DSP disassembler (LSI ZSP400 ISA; big-endian words) |
| `derive_from_pcap.py` | regenerates all derived artifacts (`full_stream.json`, `page_template.json`, `spare_basis.bin`) from the captured update (`../../USB-Dump/m3i_update1_rockusb.pcapng.gz`) |
| `xor_key_512.bin` | global 512-byte XOR key for the RK26xx firmware encryption |
| `RockUpdateD.img`, `RockUpdateP.img` | ROM-mode download payloads (USB descriptors + updater code) |
| `update_stream.json`, `full_stream.json`, `page_template.json`, `spare_basis.bin` | derived (gitignored) — regenerate with `derive_from_pcap.py` |

## Key protocol facts (all verified on-device)
- Upgrade mode: hold PLAY while plugging USB → 071b:3202. ROM downloader
  accepts D.img/P.img via EP0 vendor requests, then re-enumerates (HS) as
  the BOT updater. Idle timeout ~30–60 s; wedges on malformed CBWs —
  recover by replug.
- CBWs: `dCBWDataTransferLength = 0` always; LBA BE32 at CDB[2..5], count
  BE16 at CDB[7..8]; WRITE10 = one 2 KB page per command, payload
  2048 B data + 64 B spare/ECC (2112 total).
- Flash (K9LAG08, MLC): type code 6, page 2 KB + 64 B spare; erase block
  128 KB; NAND ID `ec d5 55 25 00`.
- Firmware image: XOR-encrypted blocks (512-byte key, per-block anchors);
  on-flash content = encrypted as-is; device decrypts at load.
- UI images: big-endian BGR565 rasters at .tl-mapped offsets (220x176
  screens; e.g. boot animation ПРИВЕТ frames).
- Bricked player recovery: hold PLAY, plug, `python3 flash.py full`.

## Status checklist
- [x] ROM download protocol (D+P) — on-device verified
- [x] Updater BOT protocol incl. flash read/write/erase — verified
- [x] Full official-update replay flasher — device boots after flash
- [x] .rfw crypto (XOR key, block anchors), firmware stages extracted
- [x] NAND ECC/spare computation (any data) — validated on capture corpus
- [x] Custom firmware pipeline (modify .rfw → build → flash) — validated
      offline (1-byte-flip E2E); first on-device custom image pending
- [x] UI image map + GUI editor (.tl format, verified offsets)
- [ ] First custom boot animation on device (next!)
- [ ] ZSP code patching (spectrum analyzer height, UI behavior)
