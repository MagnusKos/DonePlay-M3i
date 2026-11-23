# SESSION HANDOFF — read this first in a fresh agent session

You are continuing a long-running reverse-engineering project on the
**Explay M3i** MP3 player (**RockChip RK2606A**, LSI ZSP400 DSP core).
Everything is verified on real hardware unless stated otherwise.
Full private notes: `REA-Session/NOTES.md` (own nested git repo, never push).

## Environment (Incus Debian 13 container, user `hacker`, no sudo password)
- Project root: `/data/ReverseEngineering/ExplayM3i` (git repo; `uv` project)
- Tools: `uv run rkx --help` (see README.md). `.venv` exists; rebuild with `uv sync`.
- REA 6.10.1 + Ghidra 12.2 + JDK 25 at `/data/ReverseEngineering/tools/`
  (`source REA-Session/env.sh`). Seed-file format for Ghidra:
  `0x<addr>\tfunction\t<name>` lines via REA_GHIDRA_SEED_FILE.
- SDK reference source: `git clone --depth 1 https://github.com/solderneer/SimpleMP4 /tmp/SimpleMP4`
  (gets wiped from /tmp on container restarts — re-clone when needed).
- ZSP400 ISA manual (opcode tables): extracted text at
  `REA-Session/notes/zsp400_manual.txt`; original PDF at /tmp/zsp400.pdf (re-download:
  http://datasheet.digchip.com/267/267-00783-0-ZSP400.pdf).
- Device USB: passthrough via Incus (`vendorid=071b productid=3202 uid=1000 gid=1000 mode=0666`),
  needs re-plug after attach. Upgrade mode = hold PLAY while plugging.
- User runs GUI (`uv run rkx gui`) on their Arch host via `venv-host`.

## ZSP400 TOOLCHAIN (NEW 2026-11-23 — ORIGINAL SDK LOCATED, PHASE 1 DONE)
Provenance & full story: REA-Session/NOTES.md (PRIVATE — do not copy details
into public docs). In short: we obtained the period-correct OEM toolchain for
RK260x — RockCompiler/sdspI (sdcc/sdcc1/sdcpp/sdas/sdld/sdar, GCC-based,
LSI/ZSP, 2005, cygwin) — tree at `REA-Session/artifacts/oldweb/RockTools/`.
- Runner: `scripts/zsp_build.py` (asm/cc/link/elf2bin/build) — runs tools under
  wine (`wine wine32` installed; prefix ~/.wine-rocktools).
- Env: `SDSP_HOME=Z:\\...\\RockCompiler\\` (set by the script).
- VERIFIED: torture-asm round-trips byte-identical through `rkx zspdis`;
  C compiles+links with crt0+libc; SDK sample game rebuilds with matching
  function order (optimized pipeline available via the mechanism-neutral
  `--sdopt WRAPPER` hook in zsp_build.py; wrapper setup = private, see
  REA-Session/scripts/sdopt_chrono.sh).
- ELF quirk: EM_ZSP (0x4F) objects store section data WORD-BYTESWAPPED;
  firmware image = byteswap(.text). ELF .text vma 0x12000 ↔ runtime 0x9000
  (vma-offset 0x9000). zsp_build.py handles this.
- **zspdis.py FIXED**: register fields are 4-bit (r0-r15), old code masked &7
  → r8-r15 were mislabeled as r0-r7 (43% of main-fw disasm lines changed!).
  Also mov cX,rY = 0xBAxx (not B9), ext-ALU .e regs are 3-bit at (w>>5)/(w>>1).
  /tmp/main_dis.txt regenerated (base 0x1490). Old register-level analysis
  from notes may need re-reading; imm-only patches (anim counts) unaffected.

## Current state (all verified on-device)
- Full toolchain works: decrypt .rfw, edit images (GUI), edit code (byte patches),
  rebuild with auto-ECC, flash, unbrick recovery (`uv run rkx flash`).
- Two verified custom firmwares: boot-animation image change; boot-animation
  frame-count code patch (`scripts/patch_boot_frames.py`).

## KEY CONSTANTS (do not re-derive)
### Firmware file layout (.rfw = flash image, encrypted in blocks)
- XOR key: 512-byte global, `data/xor_key_512.bin`. Plaintext[x] = file[x] ^ K[(x-anchor) % 512].
- Anchors: header 0x0-0x37 plaintext; stage-1 loader 0x690-0x1290 anchor 344;
  MAIN FIRMWARE 0x1490-0xFA88 anchor 172; data/table region 0xFA88+ anchor 128;
  resource blocks later have own anchors (see rfw.py auto-detection).
- IRAM runtime address = rfw_offset - 0x1408 (main fw loads at IRAM 0x88).
- ZSP400: BIG-ENDIAN 16-bit words. Vector entries = 0xBF02 (reti) + 0xCF00 (nop).
  Disassembler: `uv run rkx zspdis <file>` or `src/rk260x/zspdis.py`.

### Boot/shutdown animations (code-patched, working)
- BOOT anim loop: .rfw 0xF390-0xF400; frame count-1 at **0xF3F4** (`movl r2,23`, stock 24 frames).
- SHUTDOWN anim loop: 0x3114-0x3174; count-1 at **0x3168** (`movl r0,11`, stock 12 frames).
- Anim frame i at NAND image offset i*77440 (0x12E40); frames are BE-BGR565 220x176
  rasters (also referenced by data/captures/m3i.json map).

### Menu/UI strings
- UTF-16LE, 64-byte slots. Settings pack (English): items Music@0x4a6dbd,
  Record, Auto Browse, Display, System, PowerOff Time, Language@0x4a6f3d (stride 0x40).
- Language packs 0x5000 apart (Russian pack = +0x5000; user's UI is Russian).
  Language names list @0x4ac87d.
- A menu-ish table (record options?): .rfw 0xFA88..0xFC00, 21 x 18-byte records
  {u16 id, u16 straddr, u16 var, u16 func, 5 reserved}, terminator id=0,
  followed by 'Waiting...' string at 0xFC16. THE actual settings SetMenu
  array is NOT yet found (it likely computes string addresses at runtime:
  base + item*0x40 + lang*0x5000).

## NEXT TASK: menu injection ("Hack" item in settings menu)
Plan (agreed with user):
1. Find the real SetMenu array / SetMenuInit: search code for constants
   0x5000 (movh rX,0x50) near 0x40 shifts (language-pack offset math), or
   linked-list init writing per/next pointers. SDK ref:
   /tmp/SimpleMP4/source_code/SetMenuSchedule.c + SetMenuStruct.h
   (SET_MENU struct: id, DispInNFAddr, AdjustValue, pFunc, per/next/father/son;
   ids hierarchical like parent*100+n in SDK, M3i uses base-0x64-ish steps).
2. Rename-first fallback: menu string slots are plain UTF-16 — renaming items
   in BOTH language packs is trivial (GUI can do it).
3. True addition: put new menu array + hand-assembled ZSP handler in free
   space (zero gaps in data region after 0xFA88), patch pointer + count.
   Do NOT shift the block (absolute movl/movh pointers would break; loader
   copies a fixed size — size constant lives in stage-1 loader, 0x690 region).
4. Fun handler ideas from user: "PowerOn Anim Frames" editor submenu,
   spectrum analyzer height fix (SDK refs: subspecanal.c, specanalfft128.s).

## OTHER OPEN THREADS (user's wishlist)
- Spectrum analyzer bars show at half height — find scale/clamp in ZSP code.
- ПРИВЕТ word swap across boot animation frames (data patch + inpaint).
- Automap remaining images (m3i.json has 79 hand-made entries; 40 VolBar total per operator).
- 0x38-0x68F .rfw config block cipher (unknown, not XOR-K).
- RKFW_HS.A SDK libs + P.img (beyond 0x110) encryption.

## GOTCHAS
- Updater (after D+P download) idles out after ~30-60 s or wedges on malformed
  CBWs — replug+PLAY and redo; always run command batches fast, no sleeps.
- CBW dCBWDataTransferLength must be 0 (tool convention); data phase is raw bulk.
- flash.py `full` replays derive/full_stream.json (verbatim official update,
  includes 4 ERASEs + verify pacing — write-only replay BRICKS, do not shortcut).
- ECC spares: rk260x/ecc.py computes them for any data (validated); all-FF
  page -> all-FF spare; 5 special boot/table pages keep template spares verbatim.
