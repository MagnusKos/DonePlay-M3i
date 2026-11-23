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
  never mention its contents in public docs (README/RESEARCH.md) without
  operator approval.
- `data/software_to_reverse/` and private artifacts stay out of the public
  history (already gitignored).
- Hardware on desk: Explay M3i player. Treat flash operations per HANDOFF
  safety notes; never shortcut the `full` flash replay.
