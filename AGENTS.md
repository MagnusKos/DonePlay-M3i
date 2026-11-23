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
