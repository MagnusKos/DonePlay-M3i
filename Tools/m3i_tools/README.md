# m3i_tools — Python tools for the Explay M3i (RockChip RK2606A)

Reverse-engineered with REA + Ghidra 12.2 from the original Windows tools
(Consumer.exe, rockusb.sys, FirmwarePuller) + cryptanalysis of the firmware
container. Full notes: ../../REA-Session/notes/

## Files
- `rockusb.py` — device communication (ROM download + updater BOT protocol)
  - `status` — find device, show ROM/updater mode
  - `boot` — download D.img+P.img, enter updater mode, read flash ID
  - `pull <out.bin> [blocks] [first_block]` — dump NAND via READ_10
  - `push <image.bin> <first_block>` — write flash via WRITE_10 (DANGER)
- `rfw.py` — parse/decrypt/extract .rfw firmware containers
- `xor_key_512.bin` — the 512-byte XOR key (RK26xx generation, global)
- `RockUpdateD.img` / `RockUpdateP.img` — original ROM download payload
  (FW USB descriptors + updater code)

## Protocol summary (verified on-device 2026-11-21)
ROM mode (hold PLAY; PID 071b:3202, FS, 64B EP0):
  vendor control 0x0C: wIndex=0x471 → stream D.img; wIndex=0x472 → stream P.img
  (256B chunks + CRC-16/CCITT-FALSE big-endian; exact Consumer.exe chunking).
  On success the ROM re-enumerates running P.img as the UPDATER
  (HS, 512B bulk endpoints, same VID:PID).
Updater mode: SCSI BOT, vendor CDBs (opcodes from FW_Upgrade.h):
  0x00 TUR, 0x01 READ_FLASH_ID (→ NAND ID ecd5552500 = Samsung K9LAG08),
  0x03 TEST_BAD_BLOCK, 0x04 READ_10, 0x05 WRITE_10, 0x06 ERASE_10,
  0x07/0x08 SPARE wr/rd, 0xFF RESET. CDBlen 6/10/16 per opcode.
  NOTE: READ_10 data phase uses 4096-byte units (flash "big block"); dlen must
  match or the device overflows/wedges (single-threaded state machine —
  protocol errors require re-booting into the updater).

## Caveats
- WRITE path not yet verified on hardware (needs careful re-verify vs
  Consumer.exe 0x40bd10 flow — it writes 55AAF00F-header boot blocks with
  per-block CRC16 and read-back verification).
- The updater wedges on malformed BOT sequences; recovery = replug+PLAY.

## Status checklist
- [x] ROM download protocol (D+P) — on-device verified
- [x] Updater re-enumeration detection
- [x] READ_FLASH_ID on-device (NAND ID matches PCB chip)
- [ ] READ_10 data-phase size semantics (4096B units — testing)
- [ ] Full NAND dump vs original .rfw comparison
- [ ] WRITE_10 / ERASE_10 on-device (then: reflash / custom firmware)
