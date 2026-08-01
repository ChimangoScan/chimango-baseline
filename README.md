# Chimango Baseline: Uniform Random-Sample Security Measurement of Docker Hub Images

Artifact for the SBSeg 2026 paper *A Uniform Random-Sample Security Measurement of Docker Hub Images*. It measures the security posture of a typical Docker Hub image using a uniform random draw and six scanners: **2,879** images were analyzed, **94.4%** contained a critical vulnerability, and manual review found **99.5%** of sampled secret detections to be false positives.

> **Paper:** SBSeg 2026 Main Track. Artifact evaluation follows the official [submission](https://doc-artefatos.github.io/sbseg2026/subinstrucoes.html) and [review](https://doc-artefatos.github.io/sbseg2026/revinstrucoes.html) instructions.

# README structure

| Section | Purpose |
|---|---|
| [Considered badges](#considered-badges) | Requested SBSeg artifact badges |
| [Basic information](#basic-information) | Reference environment and resource requirements |
| [Dependencies](#dependencies) | Software and released dataset |
| [Security concerns](#security-concerns) | Safe handling of scanner reports and container images |
| [Installation](#installation) | Required setup |
| [Minimal test](#minimal-test) | Fast offline functionality check |
| [Experiments](#experiments) | One-command reproduction of the paper results |
| [LICENSE](#license) | Artifact license |

The repository is organized as follows: `analysis/` contains the analyses, committed numeric outputs, manual labels, and figure generators; `data/` contains the canonical 4,800-repository draw; `expected/` maps paper claims to expected values; `docs/` records methodological caveats; and `reproduce.sh` is the single reproduction entry point.

# Considered badges

All four SBSeg 2026 badges are requested:

- **Available (SeloD):** public source code, data, manual labels, and MIT license.
- **Functional (SeloF):** the offline minimal test runs from a clean checkout in less than one second.
- **Sustainable (SeloS):** analyses are separated by responsibility and use documented JSON, JSONL, TSV, SQLite, and PDF outputs.
- **Reproducible (SeloR):** one command downloads the checksum-verified database, recomputes the analyses, regenerates the figures, and checks 66 paper values.

# Basic information

| Item | Requirement / reference environment |
|---|---|
| Operating system | Linux x86-64; tested on Ubuntu |
| Reference machine | AMD Ryzen 5 8600G, 12 logical CPUs, 32 GB RAM |
| Python | 3.12 used for the study; 3.10 or newer supported |
| GPU | Not required |
| Minimal test | 15 MB peak RAM, negligible disk, 0.02 s measured |
| Offline figure reproduction | 88 MB peak RAM, less than 10 MB output, 1.6 s measured |
| Full database reproduction | 4 GB RAM recommended, 11 GB free disk, approximately 4--7 min after download |

Times were measured on the reference machine. Download time depends on the evaluator's network connection.

# Dependencies

The analysis uses Python's standard library plus the packages in `requirements.txt`. The tested figure environment uses Matplotlib 3.6.3 and NumPy 1.26.4. PyMongo is needed only to draw a different sample from a private crawl and is not used during artifact evaluation.

The full input is the released `bl_snap.db.zst` dataset:

| File | Download | Decompressed | SHA-256 verification |
|---|---:|---:|---|
| `bl_snap.db.zst` | 226 MB | 10.3 GB | Automatic in `reproduce.sh` |

The script downloads the database from the repository's `dataset-v1` release, verifies the compressed and decompressed SHA-256 hashes, and stores it under `data/`. The evaluator does not need to download or move it manually. `curl` and `zstd` are required only for the full reproduction.

The original scanning campaign used Syft, Trivy, Grype, OSV-Scanner, Dockle, and TruffleHog through the separate ChimangoScan pipeline. Their image references used floating `latest` tags and their vulnerability databases were fetched at scan time. Consequently, the released reports are the record of the measured campaign; a new scan may resolve newer tools and vulnerability data.

# Security concerns

- The committed sample and manual-review files contain only redacted values and truncated hashes. Do not attempt to validate any suspected credential against a live service.
- The released SQLite database contains raw third-party scanner reports and may include sensitive detections. Keep it local and do not redistribute extracted values.
- The reproduction commands only read released reports; they do not execute software from the measured images.
- Re-running the scanners is outside the evaluator path and should be done only on disposable infrastructure because it downloads and unpacks arbitrary public images.

# Installation

Clone the repository and install the analysis dependencies:

```bash
git clone https://github.com/ChimangoScan/chimango-baseline.git && cd chimango-baseline && sudo apt-get update && sudo apt-get install -y curl zstd python3-pip && python3 -m pip install -r requirements.txt
```

**Expected time:** approximately 30--90 s, depending on the package index and network.

**Expected resources:** less than 500 MB RAM and 500 MB disk.

# Minimal test

Run the offline functionality check:

```bash
make test
```

**Expected time:** less than 1 s; 0.02 s measured on the reference machine.

**Expected resources:** 15 MB peak RAM; no network, database, Docker, or GPU.

**Expected output:**

```text
OK: random_sample.jsonl has 4800 repositories
OK: committed outputs match the paper (N=2879, 96.8% any-vuln, 0 official, 5/1100 secret TPs)
```

# Experiments

## Claim #1 — Main paper results and figures

**Description.** This experiment reproduces the paper's data-backed results from the released reports database. It checks the uniform draw and reachability outcomes; vulnerability prevalence and counts; scanner disagreement; base distributions and hardening findings; prior-analysis comparisons; and the manually labeled secret-detection rates. It also regenerates the four paper figures.

**Execution.** Run one command from the repository root:

```bash
./reproduce.sh analyze
```

The command automatically downloads and verifies the dataset on first use. Later runs reuse the verified local database.

**Expected time:** approximately 4--7 min after the dataset is available, plus the first 226 MB download and decompression.

**Expected resources:** 4 GB RAM recommended and 11 GB free disk; no GPU or Docker.

**Expected result:** the final line reports:

```text
verify: 66 pass, 0 fail (skips listed in expected/_skip_note)
```

The command writes the regenerated figures to:

- `figures/fig_panels3.pdf` — vulnerabilities per image, severity, and scanner completion;
- `figures/fig_reach.pdf` — outcomes of the 4,800-repository random draw;
- `figures/fig_repro.pdf` — prior analyses repeated on the random sample;
- `figures/fig_extra.pdf` — scanner agreement, base distribution, and secret-label categories.

The principal reproduced values are **2,879/4,800 scanned (60.0%)**, **94.4% with a critical vulnerability**, **96.8% with any vulnerability**, **947 median merged findings**, **70.5% of distinct per-image CVE findings reported by only one scanner**, and **5 genuine credentials among 1,100 sampled secret detections (99.55% false positives)**. Detailed source-to-value mappings are in `expected/paper_values.json`; methodological caveats and intentionally unavailable cross-corpus values are documented in `docs/REPRODUCIBILITY_REPORT.md`.

# LICENSE

This artifact is released under the [MIT License](LICENSE). Scanned third-party images and their contents remain the property of their respective owners.
