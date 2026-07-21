# A Uniform Random-Sample Security Measurement of Docker Hub Images

Artifacts for the SBSeg 2026 paper *"A Uniform Random-Sample Security
Measurement of Docker Hub Images"* (Cristhian Kapelinski and Diego Kreutz,
AI Horizon Labs, UNIPAMPA).

**Abstract.** Prior large-scale Docker Hub security measurements sample popular,
official, or otherwise curated images, which leaves open how secure the *typical*
image is. We draw 4,800 repositories uniformly at random from Docker Hub's
multi-million-repository namespace and scan the reachable subset with a six-tool
battery (Syft, Trivy, Grype, OSV-Scanner, Dockle, TruffleHog). We find that more
than a third of randomly drawn repositories are already gone; that among the
images that remain, a known vulnerability is near-universal and a *critical*
vulnerability is the common case; that the raw TruffleHog secret-hit rate is
overwhelmingly false positives once hand-labeled; and that a uniform random
sample contains essentially zero official (`library/`) images, so the
official-vs-community split studied in prior work cannot be reproduced on a
uniform sample. This repository contains the sampling code, the canonical random
draw, the analysis and reproduction scripts, the hand-labeled secret-validation
sample, and instructions for re-running the scan.

This is the *control group* (uniform random sample) companion to a separate
highest-exposure measurement study (ChimangoScan). The scanning pipeline itself is a separate,
reusable project (see [Installation](#installation)); this repository wires it to
the random sample and reproduces the paper's claims.

---

## README structure

- [Badges considered](#badges-considered)
- [Basic information](#basic-information)
- [Dependencies](#dependencies)
- [Security concerns](#security-concerns)
- [Installation](#installation)
- [Minimal test](#minimal-test)
- [Reproduction](#reproduction)
- [Experiments](#experiments)
  - [Claim 1 — uniform random draw and reachability](#claim-1--uniform-random-draw-and-reachability)
  - [Claim 2 — near-universal vulnerability](#claim-2--near-universal-vulnerability)
  - [Claim 3 — secret hits are almost all false positives](#claim-3--secret-hits-are-almost-all-false-positives)
  - [Claim 4 — zero official images in a uniform sample](#claim-4--zero-official-images-in-a-uniform-sample)
- [Repository layout](#repository-layout)
- [LICENSE](#license)

Repository contents:

```
chimango-baseline/
├── README.md                       this file (artifact guide)
├── LICENSE                         MIT
├── Makefile                        reproduction entry points (precomputed / full / verify)
├── reproduce.sh                    reproduction driver (precomputed / full / verify)
├── expected/
│   └── paper_values.json           every number the paper asserts, with source locator
├── docs/
│   └── REPRODUCIBILITY_REPORT.md   corrections, known limitations, verification verdict
├── requirements.txt                Python deps for the analysis scripts
├── scripts/
│   └── sample_repos.py             uniform random draw from the crawl (-> data/random_sample.jsonl)
├── data/
│   └── random_sample.jsonl         the canonical 4,800-repository draw (one :latest per repo)
├── figures/                        regenerated PDFs land here
└── analysis/
    ├── repro_baseline.py           reproduce prior-work analyses on the random sample
    ├── repro_baseline.md           narrative of the reproduction (per-study)
    ├── repro_baseline.json         numeric output of repro_baseline.py
    ├── precompute_figdata.py       distil the figure arrays from the DB into figdata_baseline.json
    ├── figdata_baseline.json       precomputed figure arrays (figures regenerate with no database)
    ├── make_figs.py                paper figures (per-image overview, reachability, reproduction)
    ├── analyze_extra.py            extra analyses + the scanner-agreement / OS / secret-FP figure
    ├── stats_baseline.py           z-tests vs the high-exposure corpus, Jaccard, distinct-CVE dedup
    ├── stats_baseline.json         numeric output of stats_baseline.py
    ├── verify_values.py            exact check of every paper number (reproduce.sh verify)
    ├── figstyle.py                 shared matplotlib style
    ├── secret_sample_baseline.py   draw the seeded n=1,100 secret sample (redacted)
    ├── secret_sample_baseline.jsonl seeded secret sample (redacted values + sha256)
    ├── secret_dist_baseline.json   population secret stats (by detector / location)
    ├── validate_secrets_baseline.py rebuild the sample + attach human verdicts + Wilson CI
    ├── secret_review_baseline.tsv  the 1,100 hand verdicts (redacted), one row per detection
    └── secret_validation_baseline.json FP/TP rates, Wilson 95% CI, redacted TP list
```

---

## Badges considered

We apply for all four SBSeg/SF artifact badges:

- **Available.** This repository is public under an open (MIT)
  license. The
  canonical random draw (`data/random_sample.jsonl`) and the hand-labeled
  secret-validation sample (`analysis/secret_review_baseline.tsv`) are included
  directly.
- **Functional.** Every script runs from a clean checkout. The
  [Minimal test](#minimal-test) exercises the analysis pipeline end-to-end on the
  small included sample, with no external services and no large download, and
  `./reproduce.sh precomputed` regenerates every paper figure from the shipped
  data with no database (see [Reproduction](#reproduction)).
- **Sustainable.** The code is small, documented, standard-library
  first (only `matplotlib`/`numpy` for figures, `pymongo` only to re-draw the
  sample), and the scanning pipeline is a separately maintained, versioned
  project. Inputs and outputs are plain text/JSON/TSV; every analysis script is
  deterministic and parameterized by environment variables.
- **Reproducible.** Reproduction is fully automated through a
  top-level `Makefile` and `reproduce.sh` ([Reproduction](#reproduction)), and
  the [Experiments](#experiments) section maps each headline claim of the paper
  to an exact command, expected runtime, expected resources, and expected
  result. The secret-validation sample is fixed
  by an explicit seed; the random draw is shipped verbatim as the canonical
  record so it does not depend on a server-side `$sample` re-execution.

> **Note on the full corpus.** The per-image scanner reports are stored in a
> SQLite database (`bl_snap.db`, 10.3 GB; 226 MB compressed) that backs Claims 2–4.
> It is too large to commit and is published as a **GitHub release asset**
> (`bl_snap.db.zst`, zstd-compressed). `./reproduce.sh dataset` downloads it,
> verifies both SHA-256 checksums, and decompresses it (needs `zstd` installed
> and ~11 GB free in `data/`).
> Claim 1 and the Minimal test run without it; Claims 2–4 document the exact
> commands to run once the database is available, and the precomputed numeric
> outputs (`analysis/repro_baseline.json`, `analysis/secret_validation_baseline.json`,
> `analysis/secret_review_baseline.tsv`) are committed so the headline numbers can
> be inspected without re-running the multi-minute streaming pass.

---

## Basic information

This artifact has two parts with different requirements:

1. **Analysis / reproduction (this repository).** Pure Python. Runs on any
   Linux/macOS machine with Python 3.10+ and a few GB of RAM. The streaming
   analyses over the full reports database (Claims 2–4) read a 10.3 GB SQLite
   file once and need roughly 2–4 GB of RAM and ~10 GB of free disk for that
   file. The included [Minimal test](#minimal-test) and Claim 1 need neither the
   database nor any network access.

2. **Scanning (separate pipeline).** Producing the reports database from scratch
   requires Docker and pulls thousands of container images; it is bandwidth- and
   disk-bound and was run across several machines. This is *not* required to
   reproduce the analyses (the database is released with the artifact), but the
   commands are given in full under [Installation](#installation) and
   [Claim 1](#claim-1--uniform-random-draw-and-reachability) for completeness.

**Execution environment used for the paper.**

- Analysis: Python 3.12 on Linux (Ubuntu), x86-64.
- Scanning: the `ChimangoScan/scanners` pipeline on a small cluster of Linux
  hosts, each with Docker and the six scanner images; targets pinned to
  `linux/amd64`, images removed after scanning, per-image size capped.

**Hardware/software minimums to reproduce the analyses.**

- x86-64 Linux or macOS.
- Python 3.10 or newer (3.12 recommended), with `pip`.
- ~4 GB RAM and ~10 GB free disk (only when running Claims 2–4 against the full
  database; the Minimal test and Claim 1 need far less).

---

## Dependencies

**Python.** 3.10+ (3.12 used for the paper). Standard library provides `sqlite3`,
`json`, `csv`, `re`, `random`, `hashlib`. Third-party packages (see
[`requirements.txt`](requirements.txt)):

```
matplotlib >= 3.7     # figures (analysis/make_figs.py)
numpy      >= 1.24    # figures (analysis/make_figs.py)
pymongo    >= 4.0     # only to RE-DRAW the sample (scripts/sample_repos.py)
```

Install with:

```bash
python3 -m pip install -r requirements.txt
```

`pymongo` is only needed if you want to re-draw the random sample against your
own crawl; the canonical draw is already shipped as `data/random_sample.jsonl`,
so the analysis and reproduction scripts run without it.

**System tools.** `curl` and `zstd` (for `./reproduce.sh dataset`, which
downloads and decompresses the released reports database; on Debian/Ubuntu:
`apt install curl zstd`).

**Scanners (the six-tool battery).** Run as pinned Docker images by the
`ChimangoScan/scanners` pipeline. The exact registry (image + invocation per
scanner) is in that repository under `config/scanners.yaml`; the six static
scanners used for this study are:

| Scanner | Role | Docker image |
|---|---|---|
| Syft | SBOM / package inventory | `anchore/syft:latest` |
| Trivy | SCA + secret + misconfig + license | `aquasec/trivy:latest` |
| Grype | SCA (CVE matcher) | `anchore/grype:latest` |
| OSV-Scanner | SCA (OSV database) | `ghcr.io/google/osv-scanner:latest` |
| Dockle | image/config best-practice lint | `goodwithtech/dockle:latest` |
| TruffleHog | embedded secrets | `trufflesecurity/trufflehog:latest` |

The pipeline pins each scanner by Docker image (the `:latest` tags resolved at
run time on the dates noted in the paper); `config/scanners.yaml` in the
`scanners` repository is the source of truth for the exact invocation of each
tool. Vulnerability databases (Trivy, Grype, OSV) are fetched at scan time.

**Docker.** Required only for the scanning step (not for the analyses). Any
recent Docker Engine on `linux/amd64`. The pipeline also expects Docker Hub
pull access (optionally authenticated to lift the unauthenticated pull rate limit).

---

## Security concerns

This artifact relates to **real leaked secrets and real vulnerabilities found in
third-party container images on Docker Hub.** Please treat it accordingly:

- **The detections are sensitive.** TruffleHog flags embedded credentials in
  scanned images, a small fraction of which are *genuine* leaked secrets (e.g. an
  SSH host private key, cloud API keys captured in application logs). Reviewers
  should treat any secret detection as potentially live and must **not** attempt
  to use, validate against live services, or redistribute any captured value.
- **Redaction is applied in the released sample.** No raw secret value is ever
  committed. The shipped secret sample
  (`analysis/secret_sample_baseline.jsonl`) and the hand-verdict file
  (`analysis/secret_review_baseline.tsv`) store only a *masked* value
  (`first6***last3`, or `<PEM-PRIVATE-KEY len=N>` for key blocks) plus a
  truncated SHA-256 of the raw value, so a reviewer can confirm a value without
  the value ever leaving the pipeline. The five hand-confirmed true positives are
  listed only in redacted form. The sampling/validation scripts hold the raw
  value in memory just long enough to derive these shape features and never
  persist it.
- **The full reports database is gated.** `bl_snap.db` (which can contain
  unredacted matched values inside raw scanner output) is not committed and is
  released with the artifact; the redaction above is what makes the *committed*
  sample safe to publish.
- **Running the scanners** pulls and unpacks arbitrary third-party images. Do
  this only on disposable infrastructure. The pipeline runs scanners against a
  saved image tarball (no code execution from the target) and, for the dynamic
  phase, hardens target containers (`cap_drop ALL`, no-new-privileges, read-only
  rootfs); this study uses the static phase only.

No part of this artifact attacks third parties or exfiltrates data; it only reads
public images and reports aggregate, redacted findings.

---

## Installation

Clone and install the Python dependencies for the analyses:

```bash
git clone https://github.com/ChimangoScan/chimango-baseline chimango-baseline
cd chimango-baseline
python3 -m pip install -r requirements.txt   # matplotlib, numpy (+ pymongo to re-draw)
```

That is everything needed for the [Minimal test](#minimal-test), Claim 1, and to
inspect the precomputed outputs of Claims 2–4.

**To re-run the scan (optional; produces the reports SQLite).** The six-scanner
pipeline is a separate, reusable project — **`ChimangoScan/scanners`** — and
is *not* duplicated here. Install and point it at this repository's sample:

```bash
# 1. get the pipeline (Python >= 3.10, uv, and a working Docker daemon)
git clone https://github.com/ChimangoScan/scanners scanners
cd scanners && uv sync

# 2. configure: copy the example config and point source.path at our sample,
#    selecting exactly the six scanners used in this study.
make config        # writes config/config.yaml from config/config.example.yaml
```

Then set, in `scanners`' `config/config.yaml`:

```yaml
source:
  type: jsonl
  path: /path/to/chimango-baseline/data/random_sample.jsonl
scanners:
  only: [syft, trivy, grype, osv, dockle, trufflehog]   # the six-tool battery
  static: true
  dynamic: false
runtime:
  remove_image_after: true     # bound disk on a large run
  max_image_mb: 15000          # skip pathologically large images
  pull_retries: 3
```

```bash
# 3. seed the queue from the sample and run (one or many machines)
uv run scanners seed
uv run scanners run --workers 4 --scan-parallelism 2
uv run scanners status
uv run scanners report     # consolidate into out/_corpus/ (findings, metrics, report.html)
```

`scanners` writes one consolidated `report.json` per target plus a corpus-level
store; the reports SQLite (`bl_snap.db`) is that per-image report store (table
`reports(image, report_json)`, table `jobs(status, error)`), which the analysis
scripts in this repository read. See the `scanners` README and `docs/` for the
distributed (many-machine) workflow, the Docker Hub account pool, and resuming a
run. A baseline-specific config (the six-scanner, static-only,
`remove_image_after` profile above) is the only configuration this study adds on
top of the pipeline's defaults; it is reproduced inline here so the repository is
self-contained.

---

## Minimal test

A quick, self-contained check that the analysis tooling runs from a clean
checkout — **no database, no network, a few seconds, standard library only.** It
validates the canonical random draw and the committed reproduction output.

```bash
# (a) the canonical draw is well-formed and has the expected size (4,800 rows)
python3 - <<'PY'
import json
rows = [json.loads(l) for l in open("data/random_sample.jsonl")]
assert len(rows) == 4800, len(rows)
assert all({"repository_namespace","repository_name","tag_name","image"} <= r.keys() for r in rows)
print("OK: random_sample.jsonl has", len(rows), "repositories")
PY

# (b) the committed reproduction output is consistent with the paper's headline
#     numbers (no database, no third-party packages)
python3 - <<'PY'
import json
R = json.load(open("analysis/repro_baseline.json"))
assert R["meta"]["n_reports"] == 2879
assert R["drdocker2025"]["ours_random"]["pct_with_known_vuln"] == 96.8
assert R["liu2020"]["ours_random"]["n_official"] == 0
V = json.load(open("analysis/secret_validation_baseline.json"))
assert V["true_positives"] == 5 and V["sample_size"] == 1100
print("OK: committed outputs match the paper (N=2879, 96.8%% any-vuln, "
      "0 official, 5/1100 secret TPs)")
PY
```

Expected output:

```
OK: random_sample.jsonl has 4800 repositories
OK: committed outputs match the paper (N=2879, 96.8% any-vuln, 0 official, 5/1100 secret TPs)
```

If both lines print, the environment is ready and the committed data parses. (To
additionally render every paper figure with no database, run
`pip install -r requirements.txt && ./reproduce.sh precomputed`; the figure
scripts read the committed `analysis/repro_baseline.json` and
`analysis/figdata_baseline.json` and write the PDFs into `figures/`. See
[Reproduction](#reproduction).)

---

## Reproduction

Reproduction is fully automated, via a top-level `Makefile` and `reproduce.sh`,
in two modes.

### Precomputed (no database, no network) — recommended


Regenerates **every paper figure** and re-checks the headline numbers from the
**shipped data only**. No external database, no network, no Docker.

```bash
python3 -m pip install -r requirements.txt   # matplotlib, numpy
./reproduce.sh precomputed                    # or:  make precomputed   (~15 s)
```

This (1) validates `data/random_sample.jsonl` (4,800 rows) and the committed
outputs (`repro_baseline.json` N=2879 / 96.8% any-vuln / 0 official,
`secret_validation_baseline.json` 5/1100 TPs), then (2) runs
`analysis/make_figs.py` and `analysis/analyze_extra.py`, which read the shipped
precomputed arrays (`analysis/figdata_baseline.json`, distilled from the reports
database by `analysis/precompute_figdata.py`) and the committed
`analysis/repro_baseline.json`, and write the figures into `figures/`:

```
figures/fig_panels3.pdf   per-image overview (vulns/image CDF, severity mix, scanner coverage)
figures/fig_reach.pdf     reachability of a uniform random draw (Scanned / Gone / ...)
figures/fig_repro.pdf     reproduction of prior analyses (CVEs-by-year, ecosystem, top packages)
figures/fig_extra.pdf     scanner agreement, base-OS distribution, secret false-positive types
```

The scripts print the headline line `N=2879 anyvuln=96.8% crit=94.4% ...`,
matching the paper. Expected runtime: a few seconds after install. Expected
resources: only Python + matplotlib (no database, ~no RAM).

### Full (run the pipeline end-to-end)

Draws a uniform random sample of `N` repositories and runs the six-scanner
pipeline at configurable scale, then recomputes the committed outputs and
figures from the resulting reports database.

```bash
./reproduce.sh dataset                        # download + verify + decompress the released DB into data/ (~40 s measured; bandwidth-dependent; needs ~11 GB free)
./reproduce.sh full                           # analyze the released DB end-to-end and verify all 49 paper values (~6 min measured)
./reproduce.sh full --n 20                    # or:  make full N=20  (small-scale rescan path)
./reproduce.sh full --n 20 --db data/bl_snap.db   # analyze a DB you already have
```

Full mode needs a working **Docker** daemon and the separate scanner pipeline
(`ChimangoScan/scanners`; see [Installation](#installation)); set
`SCANNERS_DIR` to its checkout, and `MONGO_URI` to draw a fresh sample from a
crawl (otherwise the first `N` rows of the shipped canonical draw are used so
the pipeline can still be exercised). The default `N` is small so it runs on a
laptop. **Full-scale reproduction** (the paper's 4,800-repository draw, 10.3 GB
of reports across the six tools) is bandwidth- and disk-bound and was run across
several machines — that scale needs the authors' multi-machine setup, but the
exact commands and the baseline-specific scanner configuration are documented in
full under [Installation](#installation). Once a reports database exists, point
the analysis at it with `--db` / `BL_DB` to recompute every committed output and
figure from scratch.

The per-Claim commands below give the exact invocation, expected runtime,
resources, and expected result for each headline claim of the paper.

---

## Experiments

Each subsection reproduces one **Claim** of the paper. Claims 2–4
read the full reports database `bl_snap.db` (10.3 GB, fetched by `./reproduce.sh dataset`);
point the scripts at it with the `BL_DB` environment variable (e.g.
`data/bl_snap.db`). Outputs are written next to the scripts unless
`BL_OUT` is set. The committed `analysis/*.json` / `*.tsv` (and the precomputed
`analysis/figdata_baseline.json`) are the precomputed results, so the headline
numbers and every figure can be reproduced even before the database is available.

> Conventions: `BL_DB` = path to `bl_snap.db`; `BL_OUT` = output directory
> (default: the script's own directory); `BL_FIGS` = figure directory (default
> `figures/`). All scripts are deterministic.

### Claim 1 — uniform random draw and reachability

> **4,800 repositories were drawn uniformly at random; 2,879 were scanned
> (60.0%); 34.9% of the drawn repositories are already gone (deleted/renamed).**

- **What it shows.** The sampling design and the reachability breakdown of a
  uniform random draw of the Docker Hub namespace (a result unique to a random
  sample: the popular head hides this decay).
- **No database needed:** the reachability breakdown is precomputed into
  `analysis/figdata_baseline.json`, so the figure regenerates without
  `bl_snap.db`. The database is only needed to recompute it from scratch (full
  mode).

Verify the draw size (no database, instant):

```bash
wc -l data/random_sample.jsonl        # -> 4800
```

Re-draw the sample (optional; needs a populated crawl in MongoDB — your numbers
will differ because Docker Hub `$sample` has no seed; the shipped file is the
canonical record):

```bash
MONGO_URI=mongodb://127.0.0.1:27017 SAMPLE_N=4800 \
  OUT_PATH=data/random_sample.repro.jsonl python3 scripts/sample_repos.py
```

Reachability breakdown + the reachability figure (precomputed; no database):

```bash
python3 analysis/make_figs.py                       # uses figdata_baseline.json
BL_DB=data/bl_snap.db python3 analysis/make_figs.py   # full mode (from DB)
```

- **Expected runtime:** seconds for `wc`; seconds for `make_figs.py` in
  precomputed mode (~3–4 minutes in full mode: one streaming pass over the
  reports plus the `jobs` table).
- **Expected resources:** precomputed mode needs only Python + matplotlib; full
  mode needs ~2–4 GB RAM and the 10.3 GB database on local disk.
- **Expected result.** `data/random_sample.jsonl` has 4,800 rows. `make_figs.py`
  prints the per-image summary line (`N=2879 ...`) and a `reach:` line; it writes
  `figures/fig_reach.pdf`, whose bands are **Scanned ≈ 60%** and **Gone (404)
  ≈ 35%**, with the remainder split across non-image (OCI artifact), private,
  and other-architecture outcomes. 2,879 / 4,800 = 60.0% scanned.

### Claim 2 — near-universal vulnerability

> **Vulnerability is near-universal: 94.4% of scanned images carry a critical
> vulnerability, 96.8% carry any known vulnerability, with a median of 947
> package vulnerabilities per image.**

- **What it shows.** The headline security posture of the typical image, and the
  reproduction of prior Docker Hub vulnerability studies on a uniform random
  sample.
- **Figures regenerate with no database** from the precomputed
  `analysis/figdata_baseline.json` and `analysis/repro_baseline.json`; the
  database is only needed to recompute those committed outputs from scratch.

```bash
# (a) the per-image figures (vulns/image CDF, severity mix, scanner coverage,
#     CVE-by-year, severe-by-ecosystem, top vulnerable packages), no database
python3 analysis/make_figs.py
python3 analysis/analyze_extra.py

# (b) recompute the committed outputs from scratch (full mode, needs the DB):
#     the reproduction pass and the precomputed figure arrays
BL_DB=data/bl_snap.db BL_OUT=analysis python3 analysis/repro_baseline.py
BL_DB=data/bl_snap.db BL_OUT=analysis python3 analysis/precompute_figdata.py
BL_DB=data/bl_snap.db python3 analysis/make_figs.py
```

- **Expected runtime:** seconds in precomputed mode; ~3–4 minutes each in full
  mode (one streaming pass over ~2,879 reports; `repro_baseline.py` took ~130 s
  for the paper).
- **Expected resources:** precomputed mode needs only Python + matplotlib; full
  mode needs ~2–4 GB RAM and the 10.3 GB database on local disk.
- **Expected result.** `make_figs.py` prints, e.g.,
  `N=2879 anyvuln=96.8% crit=94.4% high=96.1% secret=82.4% median=947`. In
  `analysis/repro_baseline.json`: `drdocker2025.ours_random.pct_with_known_vuln`
  = **96.8%** (any known vulnerability); the worst-severity bucket is modal
  **critical** (≈94%); `zerouali2019.ours_random.median_merged` = **947.0**
  (median package vulnerabilities per image, merged across the three SCA tools);
  the top vulnerable packages are core OS libraries (`zlib`, `openssl`, `tar`,
  …). The committed `analysis/repro_baseline.json` already contains these
  numbers, so they can be inspected without re-running. (The ~94.4% *critical*
  figure is the share of images with at least one critical package vulnerability;
  the closely related worst-severity-modal-critical share is also reported.)

### Claim 3 — secret hits are almost all false positives

> **The 82.4% raw TruffleHog secret-hit rate is ~99.5% false positives: only 5
> genuine credentials in a hand-labeled sample of 1,100 detections.**

- **What it shows.** That the raw secret-detector rate massively overstates real
  exposure, and quantifies the true rate from a hand-labeled ground-truth sample.
- **The committed files reproduce the headline number without the database;** the
  database is only needed to rebuild the sample from scratch.

Verify from the committed ground truth (no database, instant):

```bash
# the 1,100 hand verdicts; count the true positives
awk -F'\t' 'NR>1 && $1=="TP"' analysis/secret_review_baseline.tsv | wc -l   # -> 5
python3 -c "import json;d=json.load(open('analysis/secret_validation_baseline.json'));\
print('FP rate %.2f%%  TP=%d/%d  Wilson95 FP=%s' % (d['fp_rate_pct'],d['true_positives'],d['sample_size'],d['fp_rate_wilson_ci95_pct']))"
# -> FP rate 99.55%  TP=5/1100  Wilson95 FP=[98.94, 99.81]
```

Rebuild the seeded sample and verdicts from the database (optional, deterministic
via `SEED=20260522`):

```bash
BL_DB=data/bl_snap.db BL_OUT=analysis python3 analysis/secret_sample_baseline.py
BL_DB=data/bl_snap.db BL_OUT=analysis python3 analysis/validate_secrets_baseline.py
```

The committed `analysis/secret_validation_baseline.json` and
`analysis/secret_review_baseline.tsv` are the frozen ground truth used in the
paper (the hand verdicts, keyed by detector and file path, are recorded in
`analysis/validate_secrets_baseline.py`); the rebuild re-derives the seeded
sample and re-attaches those verdicts to reproduce the methodology.

- **Expected runtime:** instant for the committed-file checks; ~3–5 minutes each
  for the two rebuild scripts (one streaming pass each over the full secret
  detection population, of order 1.7–2 × 10^5 detections).
- **Expected resources:** ~2–4 GB RAM; the 10.3 GB database on local disk for the
  rebuild only.
- **Expected result.** The raw detector hit rate is **82.4%** of scanned images
  (`analysis/repro_baseline.json` →
  `dahlmanns2023.ours_random.img_with_secret_pct`). In the hand-labeled n=1,100
  sample: **5 true positives**, **false-positive rate 99.55%** (Wilson 95% CI
  98.94–99.81%), consistent with the companion study's 99.7%. The dominant
  false-positive classes are package hashes, example/placeholder values, library
  bytes, and dependency-lock artifacts.

### Claim 4 — zero official images in a uniform sample

> **Zero official (`library/`) images appear in a uniform random sample, so the
> official-vs-community split studied by prior work cannot be reproduced on a
> uniform sample.**

- **What it shows.** A measurement caveat that is itself a result: official images
  are ~hundreds out of millions, so a uniform draw contains essentially none, and
  any official-vs-community comparison requires a curated corpus.
- **The committed `analysis/repro_baseline.json` carries this directly;** the
  database reproduces it.

Verify from committed output (no database, instant):

```bash
python3 -c "import json;d=json.load(open('analysis/repro_baseline.json'));\
o=d['liu2020']['ours_random'];\
print('official=%d community=%d community_high_or_critical=%.1f%%' % (o['n_official'],o['n_community'],o['community_hc_pct']))"
# -> official=0 community=2879 community_high_or_critical=96.4%
```

Reproduce from the database:

```bash
BL_DB=data/bl_snap.db BL_OUT=analysis python3 analysis/repro_baseline.py
# then re-read liu2020.ours_random.n_official from analysis/repro_baseline.json
```

- **Expected runtime:** instant for the committed-file check; ~3–4 minutes to
  regenerate `repro_baseline.json`.
- **Expected resources:** as Claim 2.
- **Expected result.** `liu2020.ours_random.n_official` = **0** and
  `n_community` = **2,879**: no `library/` image is present, so Liu's
  official-vs-community split is **not reproducible** on a uniform sample (the
  community side alone is ~96.4% high/critical). `analysis/repro_baseline.md`
  narrates this per study.

---

## Repository layout

See [Repository contents](#readme-structure) above for the file tree. In short:
`scripts/` draws the sample; `data/` holds the canonical draw; `analysis/` holds
the reproduction and figure scripts plus their committed outputs and the
hand-labeled secret sample. The six-scanner pipeline that produces the reports
database is the separate `ChimangoScan/scanners` project (see
[Installation](#installation)).

---

## LICENSE

This artifact is released under the [MIT License](LICENSE) (see the `LICENSE`
file). Scanned third-party images and their contents remain
the property of their respective owners; only redacted, aggregate findings are
included here.
