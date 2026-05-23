# Reproducing Prior Docker Hub Analyses on the Uniform-Random Baseline

This reproduces, on our **uniform-random** Docker Hub sample (the control group),
the same concrete analyses the companion paper reproduced on its high-exposure
head (companion Sec. "Reproducing Prior Docker Hub Analyses", `tab:repro`). All
comparisons are **directional, not like-for-like**: scanner, sample and elapsed
time differ from every cited study. Per-image vulnerability counts are the raw
finding count **merged** across the three vulnerability scanners (trivy, grype,
osv) and **not deduplicated** — this inflates the mean, so medians are reported
alongside, and a deduplicated-distinct count is given as a robustness note.

- **Sample**: uniform random draw, the reports SQLite, `reports` table.
- **N images scanned**: **2,879** (one `latest` per repository reference).
- **Namespace split**: **0 official**, **2,879 community**. A uniform random draw
  from Docker Hub's multi-million-repository namespace hits essentially no
  `library/` images — Docker Hub has on the order of ~160 official repositories
  out of millions, so the probability of sampling one is negligible. This is
  itself a result (see Liu, below).
- **Method**: one read-only streaming pass mirroring the companion's
  `recount_repo.py`: severity rank `unknown<info<low<medium<high<critical`;
  worst-severity over `pkg-vuln` findings only; `clair` skipped; `dockle high ->
  critical`; `osv` unknown severities left as unknown unless an optional
  `osv_severity_cache.json` is supplied via `OSV_CACHE` (not shipped; the
  committed numbers are produced without it, as a reviewer running the script
  against the released database would); ecosystem OS-vs-language via the same
  `OS_ECO`/`LANG_ECO` sets; CVEs dated from the `CVE-AAAA-NNNN` identifier in
  `cves[]`. Script: `repro_baseline.py`. Output: `repro_baseline.json`.

---

## Per-study comparison

| Study | Reproduced analysis | Reported by the study | Our random sample |
|---|---|---|---|
| Shu 2017 | Worst-severity bucket; community vuln. median | *high* modal (>80% have >=1 high-sev); community median 158 | ***critical* modal (94.4%); median 947** (merged), 562 (distinct) |
| Zerouali 2019 | Vulns-per-image distribution | median 601, mean 1,336, max 7,338 | **median 947, mean 2,939, max 26,511** (merged) |
| Liu 2020 | High/critical prevalence, official vs community | ~30% official, >64% community | **n/a official (N=0); 96.4% community** |
| Wist 2021 | Severe findings by ecosystem (OS vs language) | severe surface in *language* ecosystems | **83.4% OS, 15.7% language** |
| Mills 2023 | Oldest CVE present; staleness | CVEs back to 1999 | **CVEs back to 1999**; staleness *not computable* (no `last_updated`) |
| Dr. Docker 2025 | % with a known vulnerability | 93.7% | **96.8%** |
| Dahlmanns 2023 | Secret detector hit rate; private-key category | 8.5% *validated*; private keys dominant | **82.4% detector hits; 45.5% private-key** (detector-level, not validated) |

---

### Shu et al. (2017)
- **Worst-severity bucket.** Reported: modal class *high*, ">80% of images carry
  >=1 high-severity vulnerability." Ours: modal class **critical** at **94.4%**
  of images; high 2.0%, medium 0.3%, none 3.2%. The modal worst-severity has
  shifted from *high* (2017) to *critical*.
- **Vulns/image median.** Reported community median 158 (mean 199), Clair, all
  severities. Ours: **median 947 merged** / 562 distinct; mean 2,939.
- **CVEs by year.** **35,019 distinct CVEs**; oldest identifier year **1999**;
  **72.8%** were published in 2020 or later (Shu's 2008-2015 historical window is
  present as a tail plus every intervening disclosure).
- **Top vulnerable packages** (by images affected): `zlib` (2,605 imgs, 90.5%),
  `openssl` (2,480, 86.1%), `tar` (2,107), `util-linux` (1,741),
  `ncurses-base` (1,736), `coreutils` (1,702), `ncurses` (1,690),
  `systemd` (1,668), `libc6` (1,637), `libc-bin` (1,630). Still core
  operating-system libraries, exactly as in Shu's 2017 ranking.
- **Interpretation.** *Confirms and intensifies* Shu: vulnerabilities remain
  near-universal and the worst-case has shifted upward from high to critical;
  the package ranking is essentially unchanged (OS libraries dominate).

### Zerouali et al. (2019)
- Reported (Debian-based images): median **601**, mean **1,336**, max **7,338**;
  effectively 100% affected.
- Ours: median **947**, mean **2,939**, max **26,511** (merged);
  median 562 / mean 1,743 / max 19,908 (distinct). **96.8%** of images carry
  >=1 vulnerability.
- **Interpretation.** *Confirms* the heavily right-skewed shape and
  near-universal affliction; our median is higher than Zerouali's, but the
  scanners and counting differ (merged multi-scanner here vs Debian-tracker
  there), so the order-of-magnitude agreement is the comparable point.

### Liu et al. (2020)
- Reported: ~30% of *official* and >64% of *community* images carry a
  high/critical vulnerability.
- Ours: **community 96.4%** (2,776 / 2,879). **Official: not estimable — N=0**
  official images in a uniform random sample.
- **Interpretation.** The community prevalence is far above Liu's >64% six years
  on (*diverges upward*). The official comparison **cannot be reproduced on a
  uniform random sample**: official images are too rare in the population to be
  sampled. This is a genuine measurement caveat of the control group, not a data
  defect, and is exactly why the companion paper used a curated exposure-ranked
  corpus for the official-vs-community split. The companion (high-exposure)
  measured 93.8% official / 95.6% community; our random community figure (96.4%)
  is consistent with its community side.

### Wist et al. (2021)
- Reported: the most severe vulnerabilities originate in *language* ecosystems
  (chiefly JavaScript and Python).
- Ours: of **2,310,145** high/critical findings, **83.4% fall in OS package
  ecosystems** and **15.7% in language ecosystems** (0.9% other). Top language
  ecosystems: Go (57,599), go-module (50,890), npm (46,651), binary (36,530).
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
- Ours: **96.8%** (2,786 / 2,879).
- **Interpretation.** *Confirms* and slightly exceeds Dr. Docker; known
  vulnerabilities are near-universal even in a uniform random sample, sitting at
  the high end of the 2017-2025 prevalence sequence.

### Dahlmanns et al. (2023)
- Reported: **8.5%** of images contain a secret **after validation**; private
  keys are the dominant leaked-secret category.
- Ours (**detector level only**, no manual validation — done by a separate
  agent): TruffleHog flags an embedded secret in **82.4%** of images (2,372), and
  a *private-key* pattern in **45.5%** (1,309; companion rule: `privatekey`/
  `private` in title or `privatekey` in id). A broader `key`-substring rule gives
  54.1%. Top detectors: Box (92,393 hits), URI (27,111), **PrivateKey (13,324)**,
  BingSubscriptionKey (10,913); 206,096 secret findings total over the N=2,879
  corpus. (The frozen hand-validation sample in `secret_validation_baseline.json`
  was drawn from an earlier ~169,528-detection snapshot; see below.)
- **Interpretation.** Comparable to the companion's **76.9% raw detector rate**,
  **NOT** to Dahlmanns' 8.5% validated rate. The detector hit rate sits far above
  the validated figure, consistent with Dahlmanns' and Dr. Docker's own
  observation that most raw secret hits are example/test material. The 45.5%
  private-key figure is strictly a detection upper bound; the validated
  prevalence (separate hand-labeling, n=1,100) is far lower (5 true positives,
  see `secret_validation_baseline.json`).

---

## Figure data (ready to plot)

All arrays are in `repro_baseline.json` under `figure_data`. For a compact
3-panel figure mirroring the companion's `fig_repro_panel` + `fig_shu_panel`:

- **(a) Official vs community high/critical prevalence** — `figure_data.
  official_vs_community_prevalence`: groups `[Official, Community]`,
  `reported_liu = [30.0, 64.0]`, `ours_random = [n/a (N=0), 96.4]`,
  `n = [0, 2879]`. Plot the community bar; annotate "Official: N=0 in a uniform
  random sample (not estimable)".
- **(b) Ecosystem split (OS vs language)** — `figure_data.ecosystem_split`:
  OS **83.4%**, Language **15.7%**, Other 0.9% of 2,310,145 high/critical
  findings.
- **(c) CVE-by-year histogram** — `figure_data.cve_by_year`: years 1999-2026,
  counts of distinct CVEs detected per identifier year (tail from 1999, mass in
  2020+; 72.8% are 2020 or later).
- **(extra) Worst-severity buckets** — `figure_data.worst_severity`:
  none 3.2 / low 0.0 / medium 0.3 / high 2.0 / **critical 94.4** (%).

## Headline takeaway

On a uniform random sample the prevalence findings of the prior studies
**hold and generally intensify**: known vulnerabilities are near-universal
(96.8%), the worst-case severity has shifted from *high* to *critical* (94.4%
modal), the vulnerable-package ranking is still OS libraries (zlib, openssl,
...), the severe surface is overwhelmingly OS rather than language ecosystems
(83.4% vs 15.7%), and CVEs reach back to 1999. The one analysis that **cannot**
be reproduced on a uniform sample is Liu's official-vs-community split: a
uniform draw contains zero official images, which is itself the reason a curated
corpus is needed for that comparison. Staleness (Mills) is not computable
because the baseline snapshot lacks registry `last_updated` timestamps.
