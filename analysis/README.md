# `analysis/`: one file, one responsibility

This directory holds the analyses that turn the released reports database
(`bl_snap.db`, 10.3 GB) into the numbers and figures the paper asserts, together
with the committed outputs of the run of record. The organizing rule is one
script per concern: each script has a single subject, reads the database
read-only (or a committed JSON), and writes named, documented outputs that no
other script overwrites.

Nothing here is executed by hand during artifact evaluation. The entry point is
always [`../reproduce.sh`](../reproduce.sh), which calls these scripts in order;
the "Run by" column below says which mode calls what.

## Scripts

### Shared library

| File | Responsibility | Reads | Writes | Run by |
|---|---|---|---|---|
| [`figstyle.py`](figstyle.py) | The publication figure style (paper serif face, grid, stroke widths) in one place, plus the warning printed when the paper's font is absent. Imported by the two figure scripts; not runnable on its own | — | — | imported by `make_figs.py`, `analyze_extra.py` |

### Recompute the numbers from the database

These three run only in `analyze` mode. Each makes its own streaming, read-only
pass over the reports database and writes exactly one JSON.

| File | Responsibility | Reads | Writes | Run by |
|---|---|---|---|---|
| [`repro_baseline.py`](repro_baseline.py) | Repeats the seven prior Docker Hub analyses (Shu 2017, Zerouali 2019, Liu 2020, Wist 2021, Dahlmanns 2023, Mills 2023, DrDocker 2025) on the uniform random sample, using the same severity ranking and counting rules, so the two columns are like-for-like | `$BL_DB` | [`repro_baseline.json`](repro_baseline.json) | `./reproduce.sh analyze` |
| [`precompute_figdata.py`](precompute_figdata.py) | Distils the arrays the figures need (per-image vulnerability counts, severity totals, scanner coverage and agreement, reachability, base-OS distribution) into one small JSON, so the figures regenerate with no database at all | `$BL_DB` | [`figdata_baseline.json`](figdata_baseline.json) | `./reproduce.sh analyze` |
| [`stats_baseline.py`](stats_baseline.py) | The statistics the other two do not emit: the two-proportion z-tests against the exposure-ranked corpus, pairwise scanner Jaccard indices, deduplicated CVEs per image, and the total finding count | `$BL_DB` | [`stats_baseline.json`](stats_baseline.json) | `./reproduce.sh analyze` |

### Draw the figures

Both scripts prefer the database when `$BL_DB` points at an existing file and
otherwise read the committed JSONs, which is what makes the offline
`precomputed` mode produce the same figures.

| File | Responsibility | Reads | Writes | Run by |
|---|---|---|---|---|
| [`make_figs.py`](make_figs.py) | The two main figures: the per-image overview (`fig_panels3.pdf`: vulnerabilities per image, severity, scanner completion) and the prior-work reproduction (`fig_repro.pdf`) | `figdata_baseline.json` or `$BL_DB`; `repro_baseline.json` | `$BL_FIGS/fig_panels3.pdf`, `$BL_FIGS/fig_repro.pdf` | `precomputed`, `analyze` |
| [`analyze_extra.py`](analyze_extra.py) | The extra analyses and their figure (`fig_extra.pdf`): scanner disagreement over distinct CVEs, base-OS distribution, Dockle hardening findings, and the hand-labeled secret categories. Prints each of those numbers as it goes | `figdata_baseline.json` or `$BL_DB`; `secret_validation_baseline.json` | `$BL_FIGS/fig_extra.pdf` | `precomputed`, `analyze` |

### Check the paper against the artifact

| File | Responsibility | Reads | Writes | Run by |
|---|---|---|---|---|
| [`verify_values.py`](verify_values.py) | Recomputes each of the 66 numbers the paper asserts from the committed outputs and compares it exactly with [`../expected/paper_values.json`](../expected/paper_values.json). Exits non-zero on any mismatch | `figdata_baseline.json`, `repro_baseline.json`, `stats_baseline.json`, `secret_validation_baseline.json`, `../expected/paper_values.json` | — (prints `verify: 66 pass, 0 fail`) | `precomputed`, `analyze`, `verify` |

### The secret ground truth (outside the evaluator path)

These two produced the committed secret files during the campaign and are
**not** called by `reproduce.sh`. The hand-labeling is the ground truth of
record, and re-running the draw against the released database yields a
different sample, because the committed one was drawn while the campaign was
still running (see [`../docs/REPRODUCIBILITY_REPORT.md`](../docs/REPRODUCIBILITY_REPORT.md)).
They are kept here so the provenance of every labeled detection is auditable.

| File | Responsibility | Reads | Writes | Run by |
|---|---|---|---|---|
| [`secret_sample_baseline.py`](secret_sample_baseline.py) | Materializes every TruffleHog detection and draws the seeded 1,100-detection sample (`random.Random(20260522).sample`), redacting every value before it is ever written | `$BL_DB` | [`secret_sample_baseline.jsonl`](secret_sample_baseline.jsonl), [`secret_dist_baseline.json`](secret_dist_baseline.json) | manual, campaign time |
| [`validate_secrets_baseline.py`](validate_secrets_baseline.py) | Re-attaches the human verdicts (recorded in the file itself, keyed by detector and location) to that sample, buckets the false-positive reasons, and computes the FP rate with its Wilson interval | `$BL_DB`, the verdicts hardcoded in the script | [`secret_review_baseline.tsv`](secret_review_baseline.tsv), [`secret_validation_baseline.json`](secret_validation_baseline.json) | manual, campaign time |

## Committed outputs

Every file below is the output of the run of record and is what the offline
`precomputed` mode reads. CI fails if a reproduction rewrites any of them.

| File | Contents | Produced by | Consumed by |
|---|---|---|---|
| [`figdata_baseline.json`](figdata_baseline.json) | The figure arrays and the reachability counts for N=2,879 | `precompute_figdata.py` | `make_figs.py`, `analyze_extra.py`, `verify_values.py`, `../scripts/minimal_test.py` |
| [`repro_baseline.json`](repro_baseline.json) | The prior-work reproduction, study by study | `repro_baseline.py` | `make_figs.py`, `verify_values.py`, `../scripts/minimal_test.py` |
| [`stats_baseline.json`](stats_baseline.json) | z-tests, Jaccard indices, unique CVEs per image, finding total | `stats_baseline.py` | `verify_values.py` |
| [`secret_validation_baseline.json`](secret_validation_baseline.json) | FP rate, Wilson 95% CI, category breakdown, the 5 true positives | `validate_secrets_baseline.py` | `analyze_extra.py`, `verify_values.py`, `../scripts/minimal_test.py` |
| [`secret_review_baseline.tsv`](secret_review_baseline.tsv) | The 1,100 per-detection verdicts, with redacted values | `validate_secrets_baseline.py` | read by hand; the labeling record |
| [`secret_sample_baseline.jsonl`](secret_sample_baseline.jsonl) | The sampled detections themselves, redacted and hashed | `secret_sample_baseline.py` | input to the labeling |
| [`secret_dist_baseline.json`](secret_dist_baseline.json) | Population statistics of all detections: totals, by detector, by location | `secret_sample_baseline.py` | context for the sample |
| [`unresolved_check.json`](unresolved_check.json) | The 2026-07-21 registry check of 200 repositories without a `latest` manifest, the evidence that the 34.9% unresolved share is not registry decay | [`../scripts/check_unresolved.py`](../scripts/check_unresolved.py) | cited in `../docs/REPRODUCIBILITY_REPORT.md` |
| [`repro_baseline.md`](repro_baseline.md) | A hand-written narrative reading of `repro_baseline.json`. Not a script output | — (written by hand) | — |

## Environment variables

| Variable | Meaning | Default |
|---|---|---|
| `BL_DB` | The reports SQLite to read | unset; the figure scripts then fall back to the committed JSONs |
| `BL_OUT` | Where a recomputing script writes its JSON | this directory |
| `BL_FIGS` | Where the figure scripts write their PDFs | `../figures` |
| `OSV_CACHE` | Optional OSV severity backfill for `repro_baseline.py` | unset, and not shipped: every published number was produced without it |
