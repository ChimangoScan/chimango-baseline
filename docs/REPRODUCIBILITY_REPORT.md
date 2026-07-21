# Reproducibility report

This report records everything a re-runner should know that the scripts alone
do not say: corrections made to the camera-ready paper after full re-execution
against the canonical database, known inconsistencies between committed
artifacts, and the current verification verdict.

## Dataset

| File | Size | SHA-256 |
|---|---|---|
| `bl_snap.db` (decompressed) | 10.3 GB | `70e43470cd877999a236be578e733233b8d3a9a382f220e7804b98ad46c58ab6` |
| `bl_snap.db.zst` (release asset) | 226 MB | `8fb43ecd312483d0a1b578c8c7685546a2197bc0d90577e2b7f8d19d77eeb580` |

Tables: `jobs` (4,800 rows: the full draw, one per repository, with status and
error), `reports` (2,879 rows: one consolidated six-scanner report per scanned
image; `SUM(n_findings)` = 9,888,892).

## Corrections made in the camera-ready

Full re-execution of the pipeline against `bl_snap.db` found five numbers in the
submitted paper that did not match the released pipeline. All five were fixed in
the camera-ready; the artifact reproduces the corrected values exactly.

| Paper claim | Submitted | Camera-ready (reproduced) | Cause |
|---|---|---|---|
| Best-pair scanner Jaccard | 0.44 | **0.43** (0.4266, grype–osv) | rounding of a stale intermediate |
| Severe findings by ecosystem (OS/lang) | 84.8 / 14.4% | **83.4 / 15.7%** (of 2,310,145) | submitted value came from a run with an unshipped OSV severity cache (denominator 2,566,580); the released pipeline has no cache |
| Base OS identified / distroless | 94.0 / 6.0% | **93.9 / 6.1%** (2,704 / 175 of 2,879) | rounding |
| Credentials in env/files (CIS-DI-0010) | 31.6% | **31.7%** (912 / 2,879) | rounding |
| Unpullable share of the draw | 2.3% ("non-image artifacts") | **2.4%** (113 / 4,800), relabeled *unpullable*: 48 legacy manifest schema + 28 OCI artifact + 37 other pull errors | rounding + imprecise label |

Numbers that re-verified exactly as published: N=4,800 / 2,879; 34.9% gone,
0.9% private, 0.8% other-arch, 1.2% did-not-finish, 60.0% scanned; 94.4 / 96.1 /
96.8% prevalence; median 947 (mean 2,939, max 26,511); 9.9M findings; 82.4%
raw secret rate; 5/1,100 secret TPs (FP 99.55%, Wilson 98.9–99.8); 70.5%
single-tool / 11.1% all-three; Debian 38.4 / Alpine 32.8 / Ubuntu 18.1%;
Dockle 99.7 / 89.0 / 97.4%; z-tests z=2.17 (p=0.03), z=1.46 (p=0.15),
z=1.21 (p=0.23); oldest CVE 1999; 0 official repositories.

## Known limitations and inconsistencies

- **Secret sample snapshot.** The committed 1,100-detection sample
  (`secret_sample_baseline.jsonl`, seed 20260522) was drawn when the corpus had
  169,528 secret detections; the released database has 206,096 (the corpus grew
  before the freeze). Re-running `secret_sample_baseline.py` against
  `bl_snap.db` therefore draws a *different* 1,100. The committed sample,
  verdicts (`secret_review_baseline.tsv`) and validation JSON are the ground
  truth of record; the 5 true positives were verified by hand and their
  (detector, location) keys are hardcoded in `validate_secrets_baseline.py`.
- **Reachability classifier.** The paper's did-not-finish category is the 57
  jobs with status `failed` (started scanning, no report); never-pulled jobs
  (status `skipped`) are classified by error text. Earlier artifact revisions
  classified purely by error text, which mixed the two; the committed classifier
  now matches the paper taxonomy.
- **Companion counts.** The two-proportion z-tests compare against the
  high-exposure corpus's exact image counts (49,392 / 50,534 / 50,957 of
  52,895), hardcoded in `stats_baseline.py`; they are not recomputable from this
  repository's data (the companion corpus is a separate release).
- **OSV severity cache.** `repro_baseline.py` accepts an optional
  `OSV_CACHE` severity backfill that is not shipped; all committed outputs and
  all paper numbers are produced without it.
- **`repro_baseline.md`** is a hand-written narrative, not a script output
  (the script writes only the JSON).
- **Unseeded draw.** The original `$sample` draw is nondeterministic by design;
  the canonical record is the committed `data/random_sample.jsonl` (4,800 rows)
  and the `jobs` table, not a re-executed draw.

## Verification (auto)

`./reproduce.sh verify` compares every number the paper asserts
(`expected/paper_values.json`, 49 checks) exactly against the committed
analysis outputs:

```
verify: 49 pass, 0 fail
```

Not recomputable from this repository (SKIP by design): the high-exposure
column of Tables 2–3 and the prior-work "Reported" values (literature /
companion corpus), and the 12,716,568-repository frame size (crawl database).
The Debian-vs-Alpine ratio and the >1,000-CVE minimal-image examples require
`bl_snap.db` (reproduced by `./reproduce.sh full --db`).
