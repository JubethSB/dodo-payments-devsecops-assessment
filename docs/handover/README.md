# Engineering Handover & Interview Prep

This directory is the full write-up behind the four tasks: not what the code
does (the per-task READMEs cover that), but *why every decision was made*, what
broke on the way, and how to defend each choice in a technical conversation.

Read it in this order:

1. [Executive summary](./executive-summary.md) — the 5-minute version.
2. Per-task deep dives — objective, threat model, design decisions, walkthrough,
   the concepts explained in interview language, verification, and the problems
   actually hit:
   - [Task 1 — Workload Hardening](./task-1-handover.md)
   - [Task 2 — CI/CD & Supply Chain](./task-2-handover.md)
   - [Task 3 — Service Mesh & Zero-Trust](./task-3-handover.md)
   - [Task 4 — Recon & Pen Test](./task-4-handover.md)
3. [Repository review & submission audit](./repository-review.md) — the repo
   graded like a hiring manager would, plus the requirement-by-requirement
   checklist against the brief.
4. [Final review & panel verdict](./final-review.md) — the pre-submission audit
   as the hiring panel: full requirement checklist (status/evidence/file/
   verification/result), scores out of 100 per dimension, and the hire decision.
5. [Interview cheat sheet](./interview-cheat-sheet.md) — commands, files, and
   one-line concept definitions to skim the hour before.

A note on voice: this is written first-person because it's a record of work I
actually did on this machine, including the things that went wrong. Where a
number or an output is quoted, it came from a real run — the evidence files
under each task's `evidence/` directory are the receipts.
