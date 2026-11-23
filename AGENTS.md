# Agent rules for this repo

Read `HANDOFF.md` first in every fresh session.

## Git — IMPORTANT
- The agent may modify files and **stage** them (`git add`), but must
  **NEVER commit**. Commits (and everything beyond: push, branch, tag,
  merge, rebase, reset) are for the operator only.
- This applies to BOTH repos: the main project repo (`/`) and the private
  nested `REA-Session/` repo.
- End-of-session state: changes staged, with a suggested commit message
  left in the session summary/notes.

## Docs discipline
- **README Status list**: one milestone = one checkbox. Tick `[x]` only
  when the user-facing goal is fully achieved (e.g. AutoMapper = a bare
  .rfw in → complete validated map out). Partial progress, WIP notes and
  internal pipeline state belong in HANDOFF.md (technical state) or
  REA-Session/NOTES.md (private) — never as extra status entries.
- Map files are JSON (`rk260x-image-map/1`, handled by `src/rk260x/imgmap.py`).
  The legacy FirmwarePuller .tl format is dead — do not re-add support for
  it; only its IDEAS (e.g. hand-mapping in the GUI) may persist.

## Other conventions
- `REA-Session/` is private (nested repo, gitignored here) — never push,
  never mention its contents in public docs (README/RESEARCH.md/HANDOFF.md)
  without operator approval.
- **Public-docs hygiene**: README.md, docs/RESEARCH.md and HANDOFF.md are
  PUBLIC. They must focus on the device, its firmware, and our own software.
  They must NOT describe: how third-party software was obtained (channels,
  sites, methods), cracks or license bypasses (or hint at them), or other
  legally sensitive details. Such details belong only in REA-Session (private).
  "We obtained the original OEM toolchain" is the acceptable level of detail.
- `data/software_to_reverse/` and private artifacts stay out of the public
  history (already gitignored).
- Hardware on desk: Explay M3i player. Treat flash operations per HANDOFF
  safety notes; never shortcut the `full` flash replay.
