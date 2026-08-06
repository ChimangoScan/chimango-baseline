# Chimango Baseline: Uniform Random-Sample Security Measurement of Docker Hub Images

[![artifact](https://github.com/ChimangoScan/chimango-baseline/actions/workflows/artifact.yml/badge.svg)](https://github.com/ChimangoScan/chimango-baseline/actions/workflows/artifact.yml)

Artifact for the SBSeg 2026 paper *A Uniform Random-Sample Security Measurement of Docker Hub Images*. It measures the security posture of a typical Docker Hub image, drawing repositories uniformly at random instead of by popularity, and scanning each one with six open-source tools. **2,879** images were analyzed and **94.4%** carry a vulnerability the scanners rate critical, so the high rates reported by earlier studies are not an effect of looking only at popular images. Hand-labeling 1,100 secret detections found **99.5%** of them to be false positives, which is why the paper reports a validated rate rather than the detector's raw output.

> **Paper:** *A Uniform Random-Sample Security Measurement of Docker Hub Images*, SBSeg 2026 Main Track. Artifact evaluation follows the official [submission](https://doc-artefatos.github.io/sbseg2026/subinstrucoes.html) and [review](https://doc-artefatos.github.io/sbseg2026/revinstrucoes.html) instructions.
>
> **Abstract.** Registry-scale security measurements of Docker Hub define their samples
> by repository class, category, popularity, or estimated reach. Their findings therefore
> describe selected subsets rather than the registry-wide posture of a typical scannable
> `latest` image. We estimate that posture from 2,879 such images obtained by uniformly
> sampling 12.7 million repositories. Six open-source scanners match the pipeline used on
> our exposure-ranked sample, where exposure is the number of pulls reached directly or
> through reused layers. 94.4% of random images carry a critical vulnerability, compared
> with 93.4% of exposure-ranked images. Tool choice strongly affects the reported posture:
> 70.5% of image-CVE pairs appear in only one of three scanners. TruffleHog reports secrets
> in 82.4% of images, but hand-labeling shows that 99.5% of these detections are false
> positives. Exposure-based prioritization identifies vulnerabilities likely to affect more
> users, but the selected images are not more vulnerable than typical scannable `latest`
> images.

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
| [How to cite](#how-to-cite) | Paper reference and machine-readable `CITATION.cff` |

The repository is organized as follows: `analysis/` contains the analyses, committed numeric outputs, manual labels, and figure generators; `data/` contains the canonical 4,800-repository draw; `expected/` maps paper claims to expected values; `docs/` records methodological caveats; and `reproduce.sh` is the single reproduction entry point.

# Considered badges

All four SBSeg 2026 badges are requested:

- **Available (SeloD):** public source code, data, manual labels, and MIT license.
- **Functional (SeloF):** the offline minimal test runs from a clean checkout in less than one second.
- **Sustainable (SeloS):** one script per concern in [`analysis/`](analysis/), each writing a documented JSON, JSONL, or TSV output; [`expected/paper_values.json`](expected/paper_values.json) maps each of the **66** numbers the paper asserts to the section or table that states it, so every claim can be located in the artifact.
- **Reproducible (SeloR):** one command downloads the checksum-verified database, recomputes the analyses, regenerates the figures, and checks 66 paper values.

# Basic information

| Item | Requirement / reference environment |
|---|---|
| Operating system | Linux x86-64; tested on Ubuntu |
| Reference machine | AMD Ryzen 5 8600G, 12 logical CPUs, 32 GB RAM |
| Python | 3.10 to 3.12; 3.12.3 used for the study. NumPy 1.26.4 and Matplotlib 3.8.4 publish no wheels for 3.13 or newer, so a newer interpreter cannot install them |
| System package | `python3-venv` (Debian and Ubuntu package it separately from `python3`) |
| Host tools | `sha256sum` and `df` from GNU coreutils, used by `reproduce.sh` to verify the dataset checksums and to check free disk before decompressing. The download itself uses Python's standard library, so no `curl` or `wget` is needed |
| Fonts | `fonts-liberation`, to typeset the figures as published. Without it matplotlib falls back to DejaVu Serif and the labels render wider; every number is unaffected |
| GPU | Not required |
| Minimal test | 15 MB peak RAM, negligible disk, 0.02 s measured |
| Offline figure reproduction | 88 MB peak RAM, less than 10 MB output, 1.6 s measured |
| Full database reproduction | 4 GB RAM recommended, 11 GB free disk. **Budget over an hour**: 30 to 60 min measured on a Ryzen 7 9700X (16 threads, 59 GB RAM), a fast desktop CPU, and longer on slower hardware, since the cost is dominated by the first read of the 10.3 GB database from disk. A re-run with the file already in the page cache takes 4 to 7 min |

Times are stated with the machine that produced them, because they are hardware- and
cache-dependent: the minimal test and the offline figure path were measured on the
reference machine above, the full reproduction on the Ryzen 7 9700X noted in its row.
Download time depends on the evaluator's network connection.

# Dependencies

The analysis uses Python's standard library plus the exact versions in `requirements.txt`: Matplotlib 3.8.4, NumPy 1.26.4, and zstandard 0.25.0. PyMongo is needed only to draw a different sample from a private crawl and is not part of artifact evaluation.

The full input is the released `bl_snap.db.zst` dataset:

| File | Download | Decompressed | SHA-256 verification |
|---|---:|---:|---|
| `bl_snap.db.zst` | 226 MB | 10.3 GB | Automatic in `reproduce.sh` |

The script downloads the database from the repository's `dataset-v1` release, verifies the compressed and decompressed SHA-256 hashes, and stores it under `data/`. Download and decompression use the isolated Python environment; the evaluator does not need system-wide packages or a manual dataset download.

The original scanning campaign used six tools through the separate ChimangoScan pipeline: Trivy, Grype and OSV-Scanner report known vulnerabilities in the installed packages, Syft inventories those packages, Dockle checks image-hardening rules, and TruffleHog flags strings that look like embedded credentials. Their image references used floating `latest` tags and their vulnerability databases were fetched at scan time. Consequently, the released reports are the record of the measured campaign; a new scan may resolve newer tools and vulnerability data.

# Security concerns

- The committed sample and manual-review files contain only redacted values and truncated hashes. Do not attempt to validate any suspected credential against a live service.
- The released SQLite database contains raw third-party scanner reports and may include sensitive detections. Keep it local and do not redistribute extracted values.
- The reproduction commands only read released reports; they do not execute software from the measured images.
- Re-running the scanners is outside the evaluator path and should be done only on disposable infrastructure because it downloads and unpacks arbitrary public images.

# Installation

Clone the repository and run the bootstrap script. It selects a Python version the pinned dependencies support, creates the isolated environment, installs into it, and verifies the imports:

```bash
git clone https://github.com/ChimangoScan/chimango-baseline.git && cd chimango-baseline && ./scripts/bootstrap.sh
```

If the system Python is newer than 3.12, the script fetches a supported one with [uv](https://github.com/astral-sh/uv), downloading uv into the clone first when it is not already installed. That path needs no root and works on any distribution; nothing outside the clone is modified.

If a system package is missing instead, the script stops and prints the single command to run for the distribution it detects (apt, dnf, pacman or zypper). Re-run the script afterwards.

Nothing is installed globally. `reproduce.sh` automatically uses `.venv/bin/python` when the environment exists; activation is unnecessary.

**Expected time:** approximately 30 to 90 s, depending on the package index and network; 8 s measured on the reference machine with a warm package cache.

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

Pick the path that fits the time and disk you have:

| Command | Cost | What it does |
|---|---|---|
| `make test` | under 1 s | confirms the setup works; no network, no dataset |
| `./reproduce.sh precomputed` | ~2 s | regenerates every paper figure and checks all 66 paper values from the committed outputs. Not a reduced path: it asserts the same numbers as the full run |
| `./reproduce.sh analyze` | **over an hour** | recomputes those same 66 values from the 10.3 GB database instead of reading them |

`make scan` re-executes the six scanners over thousands of public images. It is outside the evaluator path and should only run on disposable infrastructure.

## Claim #1: Main paper results and figures

**Description.** This experiment reproduces the paper's data-backed results from the released reports database, and regenerates the paper's three figures. It checks:

- the uniform draw and the reachability outcomes of the 4,800 repositories;
- vulnerability prevalence and per-image counts;
- scanner disagreement, meaning how often a finding is reported by only one tool;
- base-image distributions and hardening findings;
- the comparisons against prior Docker Hub analyses;
- the manually labeled secret-detection rates.

**Execution.** Run one command from the repository root:

```bash
./reproduce.sh analyze
```

The command automatically downloads and verifies the dataset on first use. Later runs reuse the verified local database.

**Expected time:** **over an hour.** 30 to 60 min measured on a Ryzen 7 9700X (16 threads, 59 GB RAM), plus the 226 MB download and its decompression to 10.3 GB; expect longer on slower hardware, since the dominant cost is the first read of the database from disk, and the first stage alone took 426 s there. Re-running once the file is in the page cache takes 4 to 7 min. Each stage prints only when it completes, so silence within a stage is normal and does not mean it hung.

**Expected resources:** 4 GB RAM recommended and 11 GB free disk; no GPU or Docker.

**Expected result:** the final line reports:

```text
verify: 66 pass, 0 fail (skips listed in expected/_skip_note)
```

The command writes the regenerated figures to:

- `figures/fig_panels3.pdf`: vulnerabilities per image, severity, and scanner completion;
- `figures/fig_repro.pdf`: prior analyses repeated on the random sample;
- `figures/fig_extra.pdf`: scanner agreement, base distribution, and secret-label categories.

The principal reproduced values are **2,879/4,800 scanned (60.0%)**, **94.4% with a critical vulnerability**, **96.8% with any vulnerability**, **947 median merged findings**, **70.5% of distinct per-image CVE findings reported by only one scanner**, and **5 genuine credentials among 1,100 sampled secret detections (99.55% false positives)**. Detailed source-to-value mappings are in `expected/paper_values.json`; methodological caveats and intentionally unavailable cross-corpus values are documented in `docs/REPRODUCIBILITY_REPORT.md`.

# LICENSE

This artifact is released under the [MIT License](LICENSE). Scanned third-party images and their contents remain the property of their respective owners.

## How to cite

Cite the paper, not the repository:

> Kapelinski, C. and Kreutz, D. (2026). A Uniform Random-Sample Security Measurement of Docker Hub Images. In *Anais do XXVII Simpósio Brasileiro de Segurança da Informação e de Sistemas Computacionais (SBSeg 2026)*. Sociedade Brasileira de Computação.

```bibtex
@inproceedings{kapelinski2026chimangobase,
  author    = {Kapelinski, Cristhian and Kreutz, Diego},
  title     = {A Uniform Random-Sample Security Measurement of Docker Hub Images},
  booktitle = {Anais do XXVII Simpósio Brasileiro de Segurança da Informação e de Sistemas Computacionais (SBSeg 2026)},
  year      = {2026},
  publisher = {Sociedade Brasileira de Computação},
}
```

[`CITATION.cff`](CITATION.cff) carries the same metadata in machine-readable form, so GitHub's
"Cite this repository" button and tools such as Zenodo pick it up automatically.
