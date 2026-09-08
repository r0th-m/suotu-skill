# SuoTu Field (索图外勤)

> In one line: teaches your AI assistant (Trae / dsh / Kimi Code, etc.) to
> investigate your logs like a professional IR analyst — big logs are carved
> down by CLI tools first, the AI only close-reads the suspicious parts,
> every finding is a candidate, and the conclusion is always yours.
> For: security/ops people holding logs and wondering "was I breached?"

An agent skill for log forensics **without the SuoTu platform** — loadable in
dsh / Trae / Kimi Code and similar agent runtimes.

One-line philosophy: **deterministic heavy lifting goes to CLI tools; the LLM
only judges** — tools carve, the model reads the carved subset, humans rule.

## What it is

A `SKILL.md` (+ reference cards) that decomposes the SuoTu platform's log
analysis methodology into "public tools + discipline + workflow":

- **Disassembled toolbox**: ripgrep / duckdb / jq / evtx_dump / hayabusa —
  five public tools assembled on the spot into an analysis pipeline
  (GB-scale logs never enter the context window; only suspicious subsets
  reach the model);
- **Discipline first**: hash before touch, originals read-only, content never
  executed, mandatory on-disk artifacts, full artifact transparency, never
  deletes anything, hits ≠ conclusions (candidates await human ruling);
- **Four-stage funnel**: inventory → identify & carve → hunt → close-read;
- **Graceful degradation**: missing tools → degrade to shallow analysis with
  honest coverage notes, never nags the user.

## Layout

- `SKILL.md` — the skill (iron rules / bootstrap protocol / workflow / scenario playbooks)
- `references/tools.md` — tool cards for the five tools (Windows/Linux dialects, all commands battle-tested)
- `references/patterns.md` — hunting pattern set (signatures + six statistical anomalies + evtx / Java app log groups)
- `references/report-contract.md` — output contract for findings and the final report

## Status

Validated on four real datasets (17.9MB web log / 5.8GB Java log / single-type
evtx / 181-file multi-type evtx) plus two regression rounds, with 26 defects
fixed along the way. The Linux-dialect tool cards are faithful adaptations not
yet field-tested on Linux (marked as such in the cards).

Relationship to the SuoTu platform: this skill is the "field kit"; the platform
is "base". Field output carries no evidence-chain guarantee — for formal cases,
redo the analysis on the platform for full chain-of-custody.

## License

MIT (see [LICENSE](LICENSE) if present; otherwise all rights reserved by the author).
