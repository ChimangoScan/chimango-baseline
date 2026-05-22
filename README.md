# How Secure Is the Typical Docker Hub Image? A Uniform Random-Sample Measurement

Artifacts for the SBSeg/SF'26 submission *"How Secure Is the Typical Docker Hub
Image? A Uniform Random-Sample Measurement."*

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
high-exposure measurement study. The scanning pipeline itself is a separate,
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
├── README.md                       this file (CTA artifact template)
├── LICENSE                         MIT
├── requirements.txt                Python deps for the analysis scripts
├── scripts/
│   └── sample_repos.py             uniform random draw from the crawl (-> data/random_sample.jsonl)
├── data/
│   └── random_sample.jsonl         the canonical 4,800-repository draw (one :latest per repo)
└── analysis/
    ├── repro_baseline.py           reproduce prior-work analyses on the random sample
    ├── repro_baseline.md           narrative of the reproduction (per-study)
    ├── repro_baseline.json         numeric output of repro_baseline.py
    ├── make_figs.py                paper figures (per-image overview, reachability, reproduction)
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

We apply for all four SBSeg/SF Selos (badges):

- **Available (Disponíveis).** This repository is public on GitHub under an open
  (MIT) license, with a permanent record to be assigned a DOI on acceptance. The
  canonical random draw (`data/random_sample.jsonl`) and the hand-labeled
  secret-validation sample (`analysis/secret_review_baseline.tsv`) are included
  directly.
- **Functional (Funcionais).** Every script runs from a clean checkout. The
  [Minimal test](#minimal-test) exercises the analysis pipeline end-to-end on the
  small included sample, with no external services and no large download.
- **Sustainable (Sustentáveis).** The code is small, documented, standard-library
  first (only `matplotlib`/`numpy` for figures, `pymongo` only to re-draw the
  sample), and the scanning pipeline is a separately maintained, versioned
  project. Inputs and outputs are plain text/JSON/TSV; every analysis script is
  deterministic and parameterized by environment variables.
- **Reproducible (Reproduzíveis).** The [Experiments](#experiments) section maps
  each headline claim of the paper to an exact command, expected runtime,
  expected resources, and expected result. The secret-validation sample is fixed
  by an explicit seed; the random draw is shipped verbatim as the canonical
  record so it does not depend on a server-side `$sample` re-execution.

> **Note on the full corpus.** The per-image scanner reports are stored in a
> SQLite database (`bl_snap.db`, ~9.7 GB) that backs Claims 2–4. It is **too
> large to commit and is released on acceptance** (and on request to reviewers).
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
   analyses over the full reports database (Claims 2–4) read a ~9.7 GB SQLite
   file once and need roughly 2–4 GB of RAM and ~10 GB of free disk for that
   file. The included [Minimal test](#minimal-test) and Claim 1 need neither the
   database nor any network access.

2. **Scanning (separate pipeline).** Producing the reports database from scratch
   requires Docker and pulls thousands of container images; it is bandwidth- and
   disk-bound and was run across several machines. This is *not* required to
   reproduce the analyses (the database is released on acceptance), but the
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
pull access (optionally authenticated to lift the anonymous pull rate limit).

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
  released on acceptance; the redaction above is what makes the *committed*
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
git clone https://github.com/ChimangoScan/chimango-baseline.git
cd chimango-baseline
python3 -m pip install -r requirements.txt   # matplotlib, numpy (+ pymongo to re-draw)
```

That is everything needed for the [Minimal test](#minimal-test), Claim 1, and to
inspect the precomputed outputs of Claims 2–4.

**To re-run the scan (optional; produces `bl_snap.db`).** The six-scanner
pipeline is a separate, reusable project — **`ChimangoScan/scanners`** — and is
*not* duplicated here. Install and point it at this repository's sample:

```bash
# 1. get the pipeline (Python >= 3.10, uv, and a working Docker daemon)
git clone https://github.com/ChimangoScan/scanners.git
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
store; `bl_snap.db` is that per-image report store (table `reports(image,
report_json)`, table `jobs(status, error)`), which the analysis scripts in this
repository read. See the `scanners` README and `docs/` for the distributed
(many-machine) workflow, the Docker Hub account pool, and resuming a run. A
baseline-specific config (the six-scanner, static-only, `remove_image_after`
profile above) is the only configuration this study adds on top of the pipeline's
defaults; it is reproduced inline here so the repository is self-contained.

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
assert R["meta"]["n_reports"] == 2876
assert R["drdocker2025"]["ours_random"]["pct_with_known_vuln"] == 96.9
assert R["liu2020"]["ours_random"]["n_official"] == 0
V = json.load(open("analysis/secret_validation_baseline.json"))
assert V["true_positives"] == 5 and V["sample_size"] == 1100
print("OK: committed outputs match the paper (N=2876, 96.9%% any-vuln, "
      "0 official, 5/1100 secret TPs)")
PY
```

Expected output:

```
OK: random_sample.jsonl has 4800 repositories
OK: committed outputs match the paper (N=2876, 96.9% any-vuln, 0 official, 5/1100 secret TPs)
```

If both lines print, the environment is ready and the committed data parses. (To
additionally render a figure, run `python3 analysis/make_figs.py` after
`pip install -r requirements.txt`; it uses the committed `repro_baseline.json`
for its reproduction panel and only needs the database for the per-image and
reachability panels.)

---

## Experiments

Each subsection reproduces one **Claim (Reivindicação)** of the paper. Claims 2–4
read the full reports database `bl_snap.db` (~9.7 GB, **released on acceptance**);
point the scripts at it with the `BL_DB` environment variable (default
`/mnt/win_ssd/bl_snap.db`). Outputs are written next to the scripts unless
`BL_OUT` is set. The committed `analysis/*.json` / `*.tsv` are the precomputed
results, so the headline numbers can be checked even before the database is
available.

> Conventions: `BL_DB` = path to `bl_snap.db`; `BL_OUT` = output directory
> (default: the script's own directory); `BL_FIGS` = figure directory (default
> `figures/`). All scripts are deterministic.

### Claim 1 — uniform random draw and reachability

> **4,800 repositories were drawn uniformly at random; 2,876 were scanned
> (59.9%); 35.3% of the drawn repositories are already gone (deleted/renamed).**

- **What it shows.** The sampling design and the reachability breakdown of a
  uniform random draw of the Docker Hub namespace (a result unique to a random
  sample: the popular head hides this decay).
- **No database needed for the design;** the reachability breakdown needs the
  `jobs` table in `bl_snap.db`.

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

Reachability breakdown + the reachability figure (needs `bl_snap.db`):

```bash
BL_DB=/path/to/bl_snap.db BL_FIGS=figures python3 analysis/make_figs.py
```

- **Expected runtime:** seconds for `wc`; ~3–4 minutes for `make_figs.py` (one
  streaming pass over the reports plus the `jobs` table).
- **Expected resources:** ~2–4 GB RAM; the ~9.7 GB database on local disk.
- **Expected result.** `data/random_sample.jsonl` has 4,800 rows. `make_figs.py`
  prints the per-image summary line (`N=2876 ...`) and a `reach:` line; it writes
  `figures/fig_reach.pdf`, whose bands are **Scanned ≈ 59.9%** and **Gone (404)
  ≈ 35.3%**, with the remainder split across non-image (OCI artifact), private,
  and other-architecture outcomes. 2,876 / 4,800 = 59.9% scanned.

### Claim 2 — near-universal vulnerability

> **Vulnerability is near-universal: 94.5% of scanned images carry a critical
> vulnerability, 96.9% carry any known vulnerability, with a median of 948
> package vulnerabilities per image.**

- **What it shows.** The headline security posture of the typical image, and the
  reproduction of prior Docker Hub vulnerability studies on a uniform random
  sample.
- **Needs `bl_snap.db`.**

```bash
# (a) reproduction pass: prevalence, severity mix, vulns/image, CVEs-by-year,
#     top vulnerable packages, ecosystem split  ->  analysis/repro_baseline.json
BL_DB=/path/to/bl_snap.db BL_OUT=analysis python3 analysis/repro_baseline.py

# (b) the per-image figures (vulns/image CDF, severity mix, scanner coverage,
#     CVE-by-year, severe-by-ecosystem, top vulnerable packages)
BL_DB=/path/to/bl_snap.db BL_FIGS=figures python3 analysis/make_figs.py
```

- **Expected runtime:** ~3–4 minutes each (one streaming pass over ~2,876
  reports; `repro_baseline.py` took ~190 s for the paper).
- **Expected resources:** ~2–4 GB RAM; the ~9.7 GB database on local disk.
- **Expected result.** `make_figs.py` prints, e.g.,
  `N=2876 anyvuln=96.9% crit=94.5% high=... secret=82.4% median=948`. In
  `analysis/repro_baseline.json`: `drdocker2025.ours_random.pct_with_known_vuln`
  = **96.9%** (any known vulnerability); the worst-severity bucket is modal
  **critical** (≈95%); `zerouali2019.ours_random.median_merged` = **948.5**
  (median package vulnerabilities per image, merged across the three SCA tools);
  the top vulnerable packages are core OS libraries (`zlib`, `openssl`, `tar`,
  …). The committed `analysis/repro_baseline.json` already contains these
  numbers, so they can be inspected without re-running. (The ~94.5% *critical*
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
BL_DB=/path/to/bl_snap.db BL_OUT=analysis python3 analysis/secret_sample_baseline.py
BL_DB=/path/to/bl_snap.db BL_OUT=analysis python3 analysis/validate_secrets_baseline.py
```

- **Expected runtime:** instant for the committed-file checks; ~3–5 minutes each
  for the two rebuild scripts (one streaming pass each over all ~169,528 secret
  detections).
- **Expected resources:** ~2–4 GB RAM; the ~9.7 GB database on local disk for the
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
# -> official=0 community=2876 community_high_or_critical=96.6%
```

Reproduce from the database:

```bash
BL_DB=/path/to/bl_snap.db BL_OUT=analysis python3 analysis/repro_baseline.py
# then re-read liu2020.ours_random.n_official from analysis/repro_baseline.json
```

- **Expected runtime:** instant for the committed-file check; ~3–4 minutes to
  regenerate `repro_baseline.json`.
- **Expected resources:** as Claim 2.
- **Expected result.** `liu2020.ours_random.n_official` = **0** and
  `n_community` = **2,876**: no `library/` image is present, so Liu's
  official-vs-community split is **not reproducible** on a uniform sample (the
  community side alone is ~96.9% high/critical). `analysis/repro_baseline.md`
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
file). Copyright is held anonymously for this double-blind submission and will be
attributed on acceptance. Scanned third-party images and their contents remain
the property of their respective owners; only redacted, aggregate findings are
included here.
