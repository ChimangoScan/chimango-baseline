#!/usr/bin/env python3
"""
Reproduce prior Docker Hub measurement analyses on the UNIFORM-RANDOM baseline
sample (control group), mirroring the companion paper's "Reproducing Prior
Docker Hub Analyses" section (tab:repro) but over the random sample instead of
the high-exposure head.

One read-only streaming pass over the reports SQLite (reports table).
Methodology mirrors the companion paper's recount so the two are like-for-like:
  - severity rank unknown<info<low<medium<high<critical
  - worst-severity per image computed over pkg-vuln findings only
  - clair findings skipped; dockle high -> critical; osv unknown severities
    backfilled from osv_severity_cache.json
  - vulns-per-image = raw MERGED (not deduplicated) pkg-vuln finding count,
    matching tab:repro; a deduplicated-distinct count is reported alongside as
    a robustness note
  - eco_class OS vs language uses the same OS_ECO/LANG_ECO sets
  - CVE-by-year from CVE-AAAA-NNNN identifiers in cves[]
  - private-key category: 'privatekey'/'private' in title or 'privatekey' in id
    (companion rule), plus a broader 'key'-substring rate reported separately

Outputs (under $BL_OUT, default: this script's directory):
  repro_baseline.json
  repro_baseline.md
Inputs are overridable via environment variables (BL_DB, BL_OUT, OSV_CACHE);
see the constants just below.
"""
import json
import os
import re
import sqlite3
import statistics
import sys
import time
from collections import Counter, defaultdict

# Paths are overridable via environment variables so the artifact runs anywhere.
#   BL_DB      reports SQLite (release asset; 10.3 GB)
#   BL_OUT     output directory for repro_baseline.json/.md (default: this dir)
#   OSV_CACHE  optional osv_severity_cache.json (severity backfill); if absent,
#              osv unknown severities are simply left as unknown.
DB = os.environ.get("BL_DB", "/path/to/reports.db")
OUTDIR = os.environ.get("BL_OUT", os.path.dirname(os.path.abspath(__file__)))
CACHE = os.environ.get("OSV_CACHE", "")

SEV_RANK = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4,
            "critical": 5}
RANK_SEV = {v: k for k, v in SEV_RANK.items()}
UNKNOWN = {"unknown", "", "none", "null", "n/a", "na"}
VULN_SCANNERS = ("trivy", "grype", "osv")
CVE_RE = re.compile(r"CVE-(\d{4})-\d+", re.I)

# ---- ecosystem classifier (verbatim from recount_repo.py) ----
OS_ECO = {"deb", "debian", "ubuntu", "rpm", "centos", "redhat", "rhel",
          "apk", "alpine", "amazon", "oracle", "suse", "sles", "photon",
          "wolfi", "chainguard", "rocky", "alma", "mariner", "azurelinux",
          "distroless", "mageia", "openeuler", "alpm", "arch"}
LANG_ECO = {"go", "go-module", "gobinary", "golang", "npm", "node",
            "node-pkg", "pypi", "python", "python-pkg", "java-archive",
            "java", "maven", "gem", "rubygems", "ruby", "nuget", "dotnet",
            "composer", "php-composer", "php-pear", "packagist",
            "crates.io", "rust-crate", "cargo", "conan", "binary"}


def eco_norm(e):
    return str(e or "").strip().lower().split(":")[0].split("/")[0]


def eco_class(e):
    e = eco_norm(e)
    if e in OS_ECO:
        return "os"
    if e in LANG_ECO:
        return "lang"
    return "other"


def norm_pkg(p):
    p = str(p).split("@")[0]
    if "/" in p:
        p = p.split("/")[-1]
    return p.lower()


def is_official(image):
    """Official image: 'library/...' prefix, or a bare name with no namespace
    slash before the repo (e.g. 'ubuntu:latest'). Community: 'user/repo:...'."""
    s = str(image)
    if s.startswith("library/"):
        return True
    # strip tag
    name = s.split("@")[0]
    name = name.rsplit(":", 1)[0] if ":" in name.split("/")[-1] else name
    return "/" not in name


def main():
    t0 = time.time()
    os.makedirs(OUTDIR, exist_ok=True)

    resolved = {}
    if os.path.exists(CACHE):
        cache = json.load(open(CACHE))
        resolved = {vid: r["severity"]
                    for vid, r in cache["severity_by_id"].items()
                    if r.get("severity")}
    else:
        sys.stderr.write("osv severity cache not found at %s; "
                         "osv unknown severities left as unknown\n" % CACHE)
    sys.stderr.write("resolved osv ids: %d\n" % len(resolved))

    con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True, timeout=300)
    cur = con.cursor()

    # ---- accumulators ----
    n_reports = 0
    n_official = 0
    n_community = 0

    most_severe = Counter()             # worst-severity bucket per image
    n_vuln = 0                          # images with >=1 pkg-vuln
    n_zero = 0
    n_crit = 0                          # images with >=1 critical pkg-vuln
    n_high = 0                          # images with >=1 high pkg-vuln

    vulns_per_image = []                # raw MERGED pkg-vuln count per image
    distinct_vulns_per_image = []       # deduplicated (cve,pkg) per image

    # Liu: high/critical prevalence official vs community
    off_hc = 0
    comm_hc = 0

    # Wist: severe (high+critical) findings by eco class + top lang eco
    sev_eco = Counter()
    sev_eco_lang = Counter()

    # Shu: CVEs by year (distinct), top vulnerable packages
    cve_year = defaultdict(set)
    cve_all = set()
    pkg_images = Counter()              # images per package (any sev)
    pkg_finds = Counter()               # raw findings per package
    pkg_crit_images = Counter()         # images with a critical of that package
    pkg_cves = defaultdict(set)

    # Dahlmanns: secrets
    img_with_secret = 0
    img_with_pk = 0                     # companion private-key rule
    img_with_key_broad = 0              # broader 'key' substring rule
    sec_detector = Counter()
    n_secret_findings = 0

    # Dr.Docker: % with a known vuln (same as n_vuln/n_reports)
    # (computed from n_vuln)

    # Mills: oldest CVE; staleness (only if last_updated present)
    have_last_updated = False

    cur.execute("SELECT image, report_json FROM reports")
    for image, rj in cur:
        n_reports += 1
        official = is_official(image)
        if official:
            n_official += 1
        else:
            n_community += 1

        try:
            j = json.loads(rj)
        except Exception:
            continue

        # last_updated probe (target.meta or finding-level) -- first row only
        if not have_last_updated:
            t = j.get("target")
            if isinstance(t, dict):
                meta = t.get("meta") or {}
                if any(k for k in meta
                       if "last_updated" in str(k).lower()
                       or "updated" in str(k).lower()):
                    have_last_updated = True

        findings = j.get("findings", []) or []

        worst = -1
        has_crit = has_high = False
        has_pk = has_key_broad = False
        n_secret = 0
        img_pkgs = set()
        img_pkgcrit = set()
        img_hc_eco = set()
        groups = defaultdict(dict)      # (cid,pkg) -> {scanner: sev}
        n_pkgvuln_raw = 0

        for f in findings:
            cat = f.get("category")
            sc = str(f.get("scanner") or "")
            if sc == "clair":
                continue
            sev = str(f.get("severity") or "unknown").strip().lower()
            if sc == "osv" and cat == "pkg-vuln" and sev in UNKNOWN:
                fid = f.get("id")
                if fid and fid in resolved:
                    sev = str(resolved[fid]).strip().lower()
            if sc == "dockle" and sev == "high":
                sev = "critical"
            if sev not in SEV_RANK:
                sev = "unknown"

            if cat == "pkg-vuln":
                n_pkgvuln_raw += 1
                worst = max(worst, SEV_RANK[sev])
                if sev == "critical":
                    has_crit = True
                if sev == "high":
                    has_high = True
                if sev in ("high", "critical"):
                    cls = eco_class(f.get("ecosystem"))
                    sev_eco[cls] += 1
                    if cls == "lang":
                        sev_eco_lang[eco_norm(f.get("ecosystem"))] += 1
                pk = f.get("package")
                npk = norm_pkg(pk) if pk else None
                if npk:
                    pkg_finds[npk] += 1
                    img_pkgs.add(npk)
                    if sev == "critical":
                        img_pkgcrit.add(npk)
                for cve in (f.get("cves") or []):
                    m = CVE_RE.match(str(cve))
                    if m:
                        cu = str(cve).upper()
                        cve_year[m.group(1)].add(cu)
                        cve_all.add(cu)
                        if npk:
                            pkg_cves[npk].add(cu)
                # deduplicated grouping (vuln scanners only)
                if sc in VULN_SCANNERS:
                    pkg = f.get("package") or ""
                    cves = f.get("cves") or []
                    if not cves:
                        cid = f.get("id")
                        cves = [cid] if cid else []
                    for cid in cves:
                        d = groups[(cid, pkg)]
                        if sc not in d or SEV_RANK.get(sev, 0) > \
                                SEV_RANK.get(d.get(sc, "unknown"), 0):
                            d[sc] = sev
            elif cat == "secret":
                n_secret += 1
                n_secret_findings += 1
                det = str(f.get("title") or f.get("id") or "?")
                sec_detector[det] += 1
                title = str(f.get("title") or "").lower()
                sid = str(f.get("id") or "").lower()
                if "privatekey" in title or "private" in title \
                        or "privatekey" in sid:
                    has_pk = True
                if "key" in title or "key" in sid:
                    has_key_broad = True

        # ---- per-image rollups ----
        if worst < 0:
            most_severe["none"] += 1
            n_zero += 1
        else:
            n_vuln += 1
            most_severe[RANK_SEV[worst]] += 1
        if has_crit:
            n_crit += 1
        if has_high:
            n_high += 1
        if has_crit or has_high:
            if official:
                off_hc += 1
            else:
                comm_hc += 1

        vulns_per_image.append(n_pkgvuln_raw)
        for npk in img_pkgs:
            pkg_images[npk] += 1
        for npk in img_pkgcrit:
            pkg_crit_images[npk] += 1

        # deduplicated distinct (cve,pkg) seen by >=1 vuln scanner
        distinct = sum(1 for _k, d in groups.items()
                       if any(s in VULN_SCANNERS for s in d))
        distinct_vulns_per_image.append(distinct)

        if n_secret > 0:
            img_with_secret += 1
        if has_pk:
            img_with_pk += 1
        if has_key_broad:
            img_with_key_broad += 1

    con.close()

    # ---------- derive metrics ----------
    def pctf(a, b):
        return round(100.0 * a / b, 1) if b else 0.0

    def stats(arr):
        if not arr:
            return {"median": 0, "mean": 0.0, "max": 0, "min": 0}
        return {"median": float(statistics.median(arr)),
                "mean": round(sum(arr) / len(arr), 1),
                "max": max(arr), "min": min(arr)}

    sev_order = ["none", "low", "medium", "high", "critical"]
    most_severe_pct = {k: pctf(most_severe.get(k, 0), n_reports)
                       for k in ["none", "low", "medium", "high", "critical",
                                 "info", "unknown"]}
    # modal class among the worst-severity buckets
    modal = max(most_severe.items(), key=lambda kv: kv[1])[0] \
        if most_severe else None

    vstats = stats(vulns_per_image)
    dstats = stats(distinct_vulns_per_image)

    # CVE by year (distinct)
    cve_by_year = {y: len(s) for y, s in sorted(cve_year.items())}
    n_distinct_cves = len(cve_all)
    years_present = sorted(int(y) for y in cve_by_year)
    oldest_year = min(years_present) if years_present else None
    # share published 2020+
    cve_2020plus = sum(v for y, v in cve_by_year.items() if int(y) >= 2020)
    pct_2020plus = pctf(cve_2020plus, n_distinct_cves)

    # top-10 vulnerable packages (by images affected)
    top_pkgs = []
    for pk, nimg in pkg_images.most_common(10):
        top_pkgs.append({
            "package": pk,
            "vuln_images": nimg,
            "pct_corpus": pctf(nimg, n_reports),
            "findings": pkg_finds.get(pk, 0),
            "cves": len(pkg_cves.get(pk, set())),
            "images_with_critical": pkg_crit_images.get(pk, 0),
        })

    # Wist eco split
    sev_eco_total = sum(sev_eco.values())
    eco_pct = {k: pctf(v, sev_eco_total) for k, v in sev_eco.items()}

    out = {
        "meta": {
            "sample": "uniform-random baseline (control group)",
            "db": DB,
            "n_reports": n_reports,
            "n_official": n_official,
            "n_community": n_community,
            "elapsed_s": round(time.time() - t0, 1),
            "caveats": (
                "Directional only: scanner battery (trivy/grype/osv merged, "
                "not deduplicated), sample (uniform random vs each study's "
                "sample) and elapsed time all differ from the cited studies. "
                "Per-image vuln counts are the merged raw pkg-vuln count "
                "(inflates the mean; medians reported alongside and a "
                "deduplicated-distinct count given as robustness)."),
        },
        "shu2017": {
            "reproduced_analysis": "worst-severity bucket per image; "
                                   "vulns/image median; CVEs by year; "
                                   "top-10 vulnerable packages",
            "reported": {
                "worst_severity_modal": "high (>80% have >=1 high-severity)",
                "community_vuln_median": 158,
                "community_vuln_mean": 199,
                "cve_years_span": "2008-2015",
            },
            "ours_random": {
                "worst_severity_modal": modal,
                "worst_severity_pct": {k: most_severe_pct[k]
                                       for k in sev_order},
                "vuln_median_merged": vstats["median"],
                "vuln_mean_merged": vstats["mean"],
                "vuln_max_merged": vstats["max"],
                "vuln_median_distinct": dstats["median"],
                "n_distinct_cves": n_distinct_cves,
                "oldest_cve_year": oldest_year,
                "pct_cves_2020plus": pct_2020plus,
                "top10_packages": top_pkgs,
            },
        },
        "zerouali2019": {
            "reproduced_analysis": "vulnerabilities-per-image distribution "
                                   "(median/mean/max)",
            "reported": {"median": 601, "mean": 1336, "max": 7338,
                         "note": "Debian-based images, all severities; "
                                 "effectively 100% affected"},
            "ours_random": {
                "median_merged": vstats["median"],
                "mean_merged": vstats["mean"],
                "max_merged": vstats["max"],
                "min_merged": vstats["min"],
                "median_distinct": dstats["median"],
                "mean_distinct": dstats["mean"],
                "max_distinct": dstats["max"],
                "pct_images_with_vuln": pctf(n_vuln, n_reports),
            },
        },
        "liu2020": {
            "reproduced_analysis": "high/critical prevalence, official vs "
                                   "community",
            "reported": {"official_hc_pct": 30.0,
                         "community_hc_pct": 64.0,
                         "note": "~30% official, >64% community"},
            "ours_random": {
                "n_official": n_official,
                "n_community": n_community,
                "official_high_or_crit": off_hc,
                "community_high_or_crit": comm_hc,
                "official_hc_pct": pctf(off_hc, n_official),
                "community_hc_pct": pctf(comm_hc, n_community),
                "caveat": ("random sample has very few official images "
                           "(N=%d); the official percentage is a "
                           "small-sample estimate" % n_official),
            },
        },
        "wist2021": {
            "reproduced_analysis": "severe (high+critical) findings by "
                                   "ecosystem class (OS vs language)",
            "reported": {"note": "most severe surface in language ecosystems "
                                 "(JavaScript, Python)"},
            "ours_random": {
                "sev_findings_by_eco_class": dict(sev_eco),
                "eco_class_pct": eco_pct,
                "sev_findings_top_lang_eco": sev_eco_lang.most_common(12),
                "n_severe_findings": sev_eco_total,
            },
        },
        "mills2023": {
            "reproduced_analysis": "oldest CVE still present; staleness "
                                   "(vulns vs image age)",
            "reported": {"oldest_cve_year": 1999,
                         "note": "CVEs back to 1999; staleness effect "
                                 "(younger images carry fewer vulns)"},
            "ours_random": {
                "oldest_cve_year": oldest_year,
                "staleness_computable": have_last_updated,
                "staleness_note": (
                    "NOT computable from this snapshot: target.meta carries "
                    "only repository_namespace/repository_name/tag_name, no "
                    "last_updated/registry timestamp. Only the oldest-CVE "
                    "datapoint is reproduced."),
            },
        },
        "drdocker2025": {
            "reproduced_analysis": "% images with a known vulnerability",
            "reported": {"pct_with_known_vuln": 93.7},
            "ours_random": {
                "n_with_vuln": n_vuln,
                "pct_with_known_vuln": pctf(n_vuln, n_reports),
            },
        },
        "dahlmanns2023": {
            "reproduced_analysis": "secret detector hit rate; private-key "
                                   "category (detector level only, no manual "
                                   "validation)",
            "reported": {"pct_validated_secret": 8.5,
                         "note": "private keys dominant (52,107 keys); 8.5% "
                                 "is the VALIDATED rate, not detector-level"},
            "ours_random": {
                "img_with_secret": img_with_secret,
                "img_with_secret_pct": pctf(img_with_secret, n_reports),
                "img_with_private_key": img_with_pk,
                "img_with_private_key_pct": pctf(img_with_pk, n_reports),
                "img_with_key_broad": img_with_key_broad,
                "img_with_key_broad_pct": pctf(img_with_key_broad, n_reports),
                "secret_detector_top": sec_detector.most_common(20),
                "n_secret_findings": n_secret_findings,
                "caveat": ("detector-level only; manual validation done "
                           "separately. Comparable to the companion's 76.9% "
                           "raw detector rate, NOT to Dahlmanns' 8.5% "
                           "validated rate."),
            },
        },
        # ---- ready-to-plot arrays for a compact figure ----
        "figure_data": {
            "official_vs_community_prevalence": {
                "groups": ["Official", "Community"],
                "reported_liu": [30.0, 64.0],
                "ours_random": [pctf(off_hc, n_official),
                                pctf(comm_hc, n_community)],
                "n": [n_official, n_community],
            },
            "ecosystem_split": {
                "classes": ["os", "lang", "other"],
                "labels": ["OS packages", "Language", "Other"],
                "ours_pct": [eco_pct.get("os", 0.0),
                             eco_pct.get("lang", 0.0),
                             eco_pct.get("other", 0.0)],
                "counts": [sev_eco.get("os", 0), sev_eco.get("lang", 0),
                           sev_eco.get("other", 0)],
            },
            "cve_by_year": {
                "years": [int(y) for y in years_present],
                "counts": [cve_by_year[str(y)] if str(y) in cve_by_year
                           else cve_by_year[("%d" % y)] for y in years_present],
            },
            "worst_severity": {
                "buckets": sev_order,
                "pct": [most_severe_pct[k] for k in sev_order],
            },
        },
    }

    # fix cve_by_year array (keys are zero-padded strings)
    out["figure_data"]["cve_by_year"]["counts"] = [
        cve_by_year[k] for k in sorted(cve_by_year, key=lambda x: int(x))]
    out["figure_data"]["cve_by_year"]["years"] = [
        int(k) for k in sorted(cve_by_year, key=lambda x: int(x))]

    with open(os.path.join(OUTDIR, "repro_baseline.json"), "w") as fh:
        json.dump(out, fh, indent=2)
    sys.stderr.write("wrote repro_baseline.json (%d reports, %.1fs)\n"
                     % (n_reports, time.time() - t0))
    return out


if __name__ == "__main__":
    main()
