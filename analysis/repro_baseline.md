# Reproducing Prior Docker Hub Analyses on the Uniform-Random Baseline

This reproduces, on our **uniform-random** Docker Hub sample (the control group),
the same concrete analyses the companion paper reproduced on its high-exposure
head (companion Sec. "Reproducing Prior Docker Hub Analyses", `tab:repro`). All
comparisons are **directional, not like-for-like**: scanner, sample and elapsed
time differ from every cited study. Per-image vulnerability counts are the raw
finding count **merged** across the three vulnerability scanners (trivy, grype,
osv) and **not deduplicated** — this inflates the mean, so medians are reported
alongside, and a deduplicated-distinct count is given as a robustness note.

- **Sample**: uniform random draw, `/mnt/win_ssd/bl_snap.db`, `reports` table.
- **N images scanned**: **2,519** (one `latest` per repository reference).
- **Namespace split**: **0 official**, **2,519 community** (2,391 distinct
  namespaces). A uniform random draw from Docker Hub's multi-million-repository
  namespace hits essentially no `library/` images — Docker Hub has on the order
  of ~160 official repositories out of millions, so the probability of sampling
  one is negligible. This is itself a result (see Liu, below).
- **Method**: one read-only streaming pass mirroring the companion's
  `recount_repo.py`: severity rank `unknown<info<low<medium<high<critical`;
  worst-severity over `pkg-vuln` findings only; `clair` skipped; `dockle high ->
  critical`; `osv` unknown severities backfilled from `osv_severity_cache.json`;
  ecosystem OS-vs-language via the same `OS_ECO`/`LANG_ECO` sets; CVEs dated from
  the `CVE-AAAA-NNNN` identifier in `cves[]`. Script:
  `repro_baseline.py`. Output: `repro_baseline.json`.

---

## Per-study comparison

| Study | Reproduced analysis | Reported by the study | Our random sample |
|---|---|---|---|
| Shu 2017 | Worst-severity bucket; community vuln. median | *high* modal (>80% have >=1 high-sev); community median 158 | ***critical* modal (95.6%); median 942** (merged), 559 (distinct) |
| Zerouali 2019 | Vulns-per-image distribution | median 601, mean 1,336, max 7,338 | **median 942, mean 2,927, max 25,277** (merged) |
| Liu 2020 | High/critical prevalence, official vs community | ~30% official, >64% community | **n/a official (N=0); 96.9% community** |
| Wist 2021 | Severe findings by ecosystem (OS vs language) | severe surface in *language* ecosystems | **84.7% OS, 14.5% language** |
| Mills 2023 | Oldest CVE present; staleness | CVEs back to 1999 | **CVEs back to 1999**; staleness *not computable* (no `last_updated`) |
| Dr. Docker 2025 | % with a known vulnerability | 93.7% | **97.1%** |
| Dahlmanns 2023 | Secret detector hit rate; private-key category | 8.5% *validated*; private keys dominant | **82.1% detector hits; 44.8% private-key** (detector-level, not validated) |

---

### Shu et al. (2017)
- **Worst-severity bucket.** Reported: modal class *high*, ">80% of images carry
  >=1 high-severity vulnerability." Ours: modal class **critical** at **95.6%**
  of images; high 1.3%, medium 0.2%, none 2.9%. The modal worst-severity has
  shifted from *high* (2017) to *critical*.
- **Vulns/image median.** Reported community median 158 (mean 199), Clair, all
  severities. Ours: **median 942 merged** / 559 distinct; mean 2,926.5.
- **CVEs by year.** **34,012 distinct CVEs**; oldest identifier year **1999**;
  **73.6%** were published in 2020 or later (Shu's 2008-2015 historical window is
  present as a tail plus every intervening disclosure).
- **Top vulnerable packages** (by images affected): `zlib` (2,300 imgs, 91.3%),
  `openssl` (2,181, 86.6%), `tar` (1,839), `util-linux` (1,519),
  `ncurses-base` (1,516), `ncurses` (1,492), `coreutils` (1,490),
  `systemd` (1,460), `libc6` (1,432), `libc-bin` (1,426). Still core
  operating-system libraries, exactly as in Shu's 2017 ranking.
- **Interpretation.** *Confirms and intensifies* Shu: vulnerabilities remain
  near-universal and the worst-case has shifted upward from high to critical;
  the package ranking is essentially unchanged (OS libraries dominate).

### Zerouali et al. (2019)
- Reported (Debian-based images): median **601**, mean **1,336**, max **7,338**;
  effectively 100% affected.
- Ours: median **942**, mean **2,926.5**, max **25,277** (merged);
  median 559 / mean 1,725 / max 14,848 (distinct). **97.1%** of images carry
  >=1 vulnerability.
- **Interpretation.** *Confirms* the heavily right-skewed shape and
  near-universal affliction; our median is higher than Zerouali's, but the
  scanners and counting differ (merged multi-scanner here vs Debian-tracker
  there), so the order-of-magnitude agreement is the comparable point.

### Liu et al. (2020)
- Reported: ~30% of *official* and >64% of *community* images carry a
  high/critical vulnerability.
- Ours: **community 96.9%** (2,441 / 2,519). **Official: not estimable — N=0**
  official images in a uniform random sample.
- **Interpretation.** The community prevalence is far above Liu's >64% six years
  on (*diverges upward*). The official comparison **cannot be reproduced on a
  uniform random sample**: official images are too rare in the population to be
  sampled. This is a genuine measurement caveat of the control group, not a data
  defect, and is exactly why the companion paper used a curated exposure-ranked
  corpus for the official-vs-community split. The companion (high-exposure)
  measured 93.8% official / 95.6% community; our random community figure (96.9%)
  is consistent with its community side.

### Wist et al. (2021)
- Reported: the most severe vulnerabilities originate in *language* ecosystems
  (chiefly JavaScript and Python).
- Ours: of **2,240,960** high/critical findings, **84.7% fall in OS package
  ecosystems** and **14.5% in language ecosystems** (0.8% other). Top language
  ecosystems: Go (54,979), go-module (46,641), npm (40,799), PyPI (31,964).
- **Interpretation.** *Diverges* from Wist in the same direction the companion
  reported (companion: 76.9% OS / 21.7% lang): even a uniform random sample is
  dominated by OS-package vulnerability surface rather than language
  dependencies. Wist's application-oriented sample surfaced language deps; both
  our random and the companion's exposure-ranked corpora are OS-dominated. The
  random sample skews *even more* toward OS than the high-exposure head.

### Mills et al. (2023)
- Reported: some images still report CVEs as old as **1999**; staleness effect
  (older images carry more vulnerabilities).
- Ours: oldest CVE identifier year is **1999** — reproduced exactly. **Staleness
  is NOT computable** from this snapshot: `target.meta` carries only
  `repository_namespace` / `repository_name` / `tag_name`, with no
  `last_updated` / registry timestamp, so vulns-vs-age cannot be regressed here.
- **Interpretation.** *Confirms* the long unpatched tail (CVEs back to 1999). The
  staleness regression the companion ran (it had registry `last_updated` for
  96.5% of its corpus) is unavailable in this baseline snapshot and is reported
  as not computable rather than estimated.

### Dr. Docker (2025)
- Reported: **93.7%** of images carry a known vulnerability.
- Ours: **97.1%** (2,447 / 2,519).
- **Interpretation.** *Confirms* and slightly exceeds Dr. Docker; known
  vulnerabilities are near-universal even in a uniform random sample, sitting at
  the high end of the 2017-2025 prevalence sequence.

### Dahlmanns et al. (2023)
- Reported: **8.5%** of images contain a secret **after validation**; private
  keys are the dominant leaked-secret category.
- Ours (**detector level only**, no manual validation — done by a separate
  agent): TruffleHog flags an embedded secret in **82.1%** of images (2,067), and
  a *private-key* pattern in **44.8%** (1,129; companion rule: `privatekey`/
  `private` in title or `privatekey` in id). A broader `key`-substring rule gives
  53.4%. Top detectors: Box (77,011 hits), URI (22,545), **PrivateKey (11,387)**,
  BingSubscriptionKey (9,150). 169,528 secret findings total.
- **Interpretation.** Comparable to the companion's **76.9% raw detector rate**,
  **NOT** to Dahlmanns' 8.5% validated rate. The detector hit rate sits far above
  the validated figure, consistent with Dahlmanns' and Dr. Docker's own
  observation that most raw secret hits are example/test material. The 44.8%
  private-key figure is strictly a detection upper bound; the validated
  prevalence (separate hand-labeling) is far lower.

---

## Figure data (ready to plot)

All arrays are in `repro_baseline.json` under `figure_data`. For a compact
3-panel figure mirroring the companion's `fig_repro_panel` + `fig_shu_panel`:

- **(a) Official vs community high/critical prevalence** — `figure_data.
  official_vs_community_prevalence`: groups `[Official, Community]`,
  `reported_liu = [30.0, 64.0]`, `ours_random = [n/a (N=0), 96.9]`,
  `n = [0, 2519]`. Plot the community bar; annotate "Official: N=0 in a uniform
  random sample (not estimable)".
- **(b) Ecosystem split (OS vs language)** — `figure_data.ecosystem_split`:
  OS **84.7%**, Language **14.5%**, Other 0.8% of 2,240,960 high/critical
  findings.
- **(c) CVE-by-year histogram** — `figure_data.cve_by_year`: years 1999-2026,
  counts of distinct CVEs detected per identifier year (tail from 1999, mass in
  2020+; 73.6% are 2020 or later).
- **(extra) Worst-severity buckets** — `figure_data.worst_severity`:
  none 2.9 / low 0.0 / medium 0.2 / high 1.3 / **critical 95.6** (%).

## Headline takeaway

On a uniform random sample the prevalence findings of the prior studies
**hold and generally intensify**: known vulnerabilities are near-universal
(97.1%), the worst-case severity has shifted from *high* to *critical* (95.6%
modal), the vulnerable-package ranking is still OS libraries (zlib, openssl,
...), the severe surface is overwhelmingly OS rather than language ecosystems
(84.7% vs 14.5%), and CVEs reach back to 1999. The one analysis that **cannot**
be reproduced on a uniform sample is Liu's official-vs-community split: a
uniform draw contains zero official images, which is itself the reason a curated
corpus is needed for that comparison. Staleness (Mills) is not computable
because the baseline snapshot lacks registry `last_updated` timestamps.
