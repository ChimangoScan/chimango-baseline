#!/usr/bin/env python3
"""Extra analyses for the random-sample baseline short paper, plus one compact
3-panel figure (fig_extra.pdf). All numbers on the N random images.

Analyses:
  1. Scanner divergence among trivy/grype/osv on DISTINCT CVEs (per-image + overall).
  2. OS / base distribution from the syft SBOM purl distro= tag.
  3. Misconfiguration (dockle image-config) coverage + most common items.
  4. Secret FP categories from secret_validation_baseline.json (for the figure).

Data sources, in order of preference:
  * If the reports database exists (BL_DB points at an existing file), every
    analysis is computed from it in one streaming pass (full mode).
  * Otherwise the shipped precomputed arrays (analysis/figdata_baseline.json,
    produced by analysis/precompute_figdata.py) are used, so the figure and the
    headline numbers regenerate with NO database (precomputed mode, the default).
"""
import json, sqlite3, re, os
from collections import Counter
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import figstyle

_HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("BL_DB", "/path/to/reports.db")
OUT = os.environ.get("BL_FIGS", os.path.join(os.path.dirname(_HERE), "figures"))
VAL = os.path.join(_HERE, "secret_validation_baseline.json")
FIGDATA = os.path.join(_HERE, "figdata_baseline.json")
figstyle.apply()
BLUE, RED, GREEN = "#4575b4", "#b2182b", "#1a9850"
ORANGE, PURPLE = "#f46d43", "#8073ac"

VULN_SCANNERS = ("trivy", "grype", "osv")

# distro family canonicalization from syft purl distro=<id>-<ver>
DISTRO_FAMILY = {
    "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine",
    "centos": "CentOS", "rhel": "RHEL", "ol": "Oracle Linux", "oracle": "Oracle Linux",
    "rocky": "Rocky", "almalinux": "AlmaLinux", "alma": "AlmaLinux",
    "fedora": "Fedora", "amzn": "Amazon Linux", "amazonlinux": "Amazon Linux",
    "opensuse": "openSUSE", "sles": "SLES", "sled": "SLES",
    "arch": "Arch", "wolfi": "Wolfi", "chainguard": "Wolfi", "photon": "Photon",
    "mariner": "Mariner", "azurelinux": "Mariner",
}


def family_of(distro_tag):
    """debian-12 -> Debian ; ol-8.5 -> Oracle Linux."""
    base = re.split(r"[-.]", distro_tag, 1)[0].lower()
    return DISTRO_FAMILY.get(base)


def from_db():
    """One streaming pass over the reports table (full mode)."""
    con = sqlite3.connect(f"file:{DB}?immutable=1", uri=True)
    N = 0
    overall_sets = {s: set() for s in VULN_SCANNERS}   # distinct CVEs overall, per scanner
    img_share = Counter()        # over (image, cve): how many scanners reported it -> count
    n_img_with_vuln = 0
    percell_by1 = []; percell_by2 = []; percell_by3 = []  # per-image fractions
    img_os = []                  # one dominant family per image (or None)
    dockle_id_imgcount = Counter()
    dockle_title = {}
    n_img_misconf = 0
    n_img_dockle_ran = 0
    n_img_misconf_strict = 0
    trio_ok_count = Counter()
    cve_re = re.compile(r"^CVE-\d{4}-\d+$", re.I)

    for (rj,) in con.execute("SELECT report_json FROM reports"):
        r = json.loads(rj)
        N += 1
        findings = r.get("findings") or []
        invs = r.get("invocations") or []
        ok_vuln = {i.get("scanner") for i in invs
                   if i.get("scanner") in VULN_SCANNERS and i.get("status") in ("ok", "ok-cached")}
        trio_ok_count[len(ok_vuln)] += 1
        per_img = {s: set() for s in VULN_SCANNERS}
        distro_pkg_counter = Counter()
        dockle_ids_here = set()
        dockle_ran = any(i.get("scanner") == "dockle" and i.get("status") in ("ok", "ok-cached") for i in invs)
        if dockle_ran:
            n_img_dockle_ran += 1
        for f in findings:
            cat = f.get("category")
            sc = f.get("scanner")
            if cat == "pkg-vuln" and sc in VULN_SCANNERS:
                cves = f.get("cves") or []
                fid = f.get("id") or ""
                ids = set(c for c in cves if cve_re.match(c or ""))
                if cve_re.match(fid):
                    ids.add(fid.upper())
                ids = {c.upper() for c in ids}
                per_img[sc].update(ids)
                overall_sets[sc].update(ids)
            elif cat == "sbom-component" and sc == "syft":
                pid = f.get("id") or ""
                m = re.search(r"distro=([a-zA-Z0-9._-]+)", pid)
                if m:
                    fam = family_of(m.group(1))
                    if fam:
                        distro_pkg_counter[fam] += 1
            elif cat == "image-config" and sc == "dockle":
                dockle_ids_here.add(f.get("id"))
                dockle_title[f.get("id")] = f.get("title")
        active = [s for s in VULN_SCANNERS if s in ok_vuln] or list(VULN_SCANNERS)
        union = set().union(*[per_img[s] for s in active]) if active else set()
        if union:
            n_img_with_vuln += 1
            b1 = b2 = b3 = 0
            for cve in union:
                k = sum(1 for s in active if cve in per_img[s])
                img_share[k] += 1
                if k == 1: b1 += 1
                elif k == 2: b2 += 1
                elif k >= 3: b3 += 1
            tot = b1 + b2 + b3
            percell_by1.append(100 * b1 / tot)
            percell_by2.append(100 * b2 / tot)
            percell_by3.append(100 * b3 / tot)
        if distro_pkg_counter:
            img_os.append(distro_pkg_counter.most_common(1)[0][0])
        else:
            img_os.append(None)
        if dockle_ids_here:
            n_img_misconf += 1
            if dockle_ids_here - {"CIS-DI-0005"}:
                n_img_misconf_strict += 1
            for did in dockle_ids_here:
                dockle_id_imgcount[did] += 1
    con.close()

    os_counter = Counter(x for x in img_os if x is not None)
    return {
        "N": N,
        "overall_card": {s: len(overall_sets[s]) for s in VULN_SCANNERS},
        "all_cves_agree": _overall_agreement(overall_sets),
        "img_share": dict(img_share),
        "n_img_with_vuln": n_img_with_vuln,
        "percell_mean": [round(np.mean(percell_by1), 1) if percell_by1 else 0.0,
                         round(np.mean(percell_by2), 1) if percell_by2 else 0.0,
                         round(np.mean(percell_by3), 1) if percell_by3 else 0.0],
        "trio_ok": dict(trio_ok_count),
        "os_counter": os_counter.most_common(10),
        "n_os_unknown": sum(1 for x in img_os if x is None),
        "dockle_top": dockle_id_imgcount.most_common(8),
        "dockle_title": dockle_title,
        "n_img_dockle_ran": n_img_dockle_ran,
        "n_img_misconf": n_img_misconf,
        "n_img_misconf_strict": n_img_misconf_strict,
    }


def _overall_agreement(overall_sets):
    """Pooled distinct-CVE agreement (by 1 / 2 / 3 scanners)."""
    all_cves = set().union(*overall_sets.values())
    ov1 = ov2 = ov3 = 0
    for cve in all_cves:
        k = sum(1 for s in VULN_SCANNERS if cve in overall_sets[s])
        if k == 1: ov1 += 1
        elif k == 2: ov2 += 1
        else: ov3 += 1
    return [ov1, ov2, ov3]


def from_precomputed():
    """Read the shipped precomputed arrays (precomputed mode, no database).

    The pooled-distinct agreement (by 1/2/3 scanners) needs the per-scanner CVE
    sets, which are not stored verbatim; the figure does not use it, so it is
    reported as None in precomputed mode (the figure uses the per-(image,CVE)
    pooled fractions, which ARE stored)."""
    d = json.load(open(FIGDATA))
    dv = d["divergence"]
    fe = d["fig_extra"]
    return {
        "N": d["fig_panels3"]["N"],
        "overall_card": dv["overall_card"],
        "all_cves_agree": None,
        "img_share": {int(k): v for k, v in dv["img_share"].items()},
        "n_img_with_vuln": dv["n_img_with_vuln"],
        "percell_mean": dv["percell_mean"],
        "trio_ok": {int(k): v for k, v in dv["trio_ok"].items()},
        "os_counter": [tuple(t) for t in fe["os_counter"]],
        "n_os_unknown": fe["n_os_unknown"],
        "dockle_top": [tuple(t) for t in fe["dockle_top"]],
        "dockle_title": fe["dockle_title"],
        "n_img_dockle_ran": fe["n_img_dockle_ran"],
        "n_img_misconf": fe["n_img_misconf"],
        "n_img_misconf_strict": fe["n_img_misconf_strict"],
    }


# choose the data source: real DB if present, else the precomputed JSON
if os.path.exists(DB):
    D = from_db()
    print("source: reports database", DB)
else:
    D = from_precomputed()
    print("source: precomputed", FIGDATA, "(no database)")

N = D["N"]
img_share = Counter(D["img_share"])
n_img_with_vuln = D["n_img_with_vuln"]
trio_ok_count = D["trio_ok"]
os_counter = Counter(dict(D["os_counter"]))
n_os_unknown = D["n_os_unknown"]
dockle_id_imgcount = Counter(dict(D["dockle_top"]))
dockle_title = D["dockle_title"]
n_img_dockle_ran = D["n_img_dockle_ran"]
n_img_misconf = D["n_img_misconf"]
n_img_misconf_strict = D["n_img_misconf_strict"]

# ============================================================ (1) DIVERGENCE
vol = D["overall_card"]
vol_ratio = max(vol.values()) / max(1, min(vol.values()))
ov_agree = D["all_cves_agree"]
if ov_agree:
    ov1, ov2, ov3 = ov_agree
    ov_tot = ov1 + ov2 + ov3
    ov_pct = (100*ov1/ov_tot, 100*ov2/ov_tot, 100*ov3/ov_tot)
else:
    ov1 = ov2 = ov3 = ov_tot = 0
    ov_pct = (None, None, None)

# per-(image,cve) pooled fractions (this is the headline replicate)
ic_tot = sum(img_share.values())
ic1 = img_share[1]; ic2 = img_share[2]; ic3 = sum(v for k, v in img_share.items() if k >= 3)
ic_pct = (100*ic1/ic_tot, 100*ic2/ic_tot, 100*ic3/ic_tot)

# per-image mean of within-image fractions
pi1, pi2, pi3 = D["percell_mean"]

print("=" * 70)
print("(1) SCANNER DIVERGENCE  (trivy / grype / osv) on DISTINCT CVEs")
print("-" * 70)
print(f"  N images = {N}; images with >=1 CVE = {n_img_with_vuln}")
print(f"  trio scanners ran ok on image: counts = {dict(sorted(trio_ok_count.items()))}")
print(f"  distinct CVE volume per scanner: trivy={vol['trivy']}  grype={vol['grype']}  osv={vol['osv']}")
print(f"  volume ratio (max/min)         : {vol_ratio:.2f}x")
print()
if ov_agree:
    print(f"  OVERALL pooled distinct CVEs (n={ov_tot}):")
    print(f"     by 1 scanner : {ov1:6d}  ({ov_pct[0]:.1f}%)")
    print(f"     by 2 scanners: {ov2:6d}  ({ov_pct[1]:.1f}%)")
    print(f"     by all 3     : {ov3:6d}  ({ov_pct[2]:.1f}%)")
else:
    print("  OVERALL pooled distinct CVEs: (needs the database; per-(image,CVE) "
          "pooled fractions below are used by the figure)")
print()
print(f"  PER-(image,CVE) pooled (n={ic_tot}):")
print(f"     by 1 scanner : {ic1:7d}  ({ic_pct[0]:.1f}%)")
print(f"     by 2 scanners: {ic2:7d}  ({ic_pct[1]:.1f}%)")
print(f"     by all 3     : {ic3:7d}  ({ic_pct[2]:.1f}%)")
print()
print(f"  PER-IMAGE mean of within-image fractions:")
print(f"     by1={pi1:.1f}%  by2={pi2:.1f}%  by3={pi3:.1f}%")
print(f"  [high-exposure head reported ~66.8% single / 2.7% all-three]")

# ============================================================ (2) OS DISTRIBUTION
n_os_known = sum(os_counter.values())
print()
print("=" * 70)
print("(2) OS / BASE DISTRIBUTION  (dominant distro family per image, syft SBOM)")
print("-" * 70)
print(f"  images with an OS family detected = {n_os_known}/{N} "
      f"({100*n_os_known/N:.1f}%); no OS packages (distroless/scratch/lang-only) = {n_os_unknown} "
      f"({100*n_os_unknown/N:.1f}%)")
for fam, c in os_counter.most_common(10):
    print(f"     {fam:14s} {c:5d}  ({100*c/N:.1f}% of all images, {100*c/n_os_known:.1f}% of OS-based)")

# ============================================================ (3) MISCONFIG
print()
print("=" * 70)
print("(3) MISCONFIGURATION  (dockle image-config)")
print("-" * 70)
print(f"  images where dockle ran ok               = {n_img_dockle_ran}/{N} ({100*n_img_dockle_ran/N:.1f}%)")
print(f"  images with >=1 misconfiguration         = {n_img_misconf}/{N} ({100*n_img_misconf/N:.1f}%)")
print(f"  images with >=1 (excl. content-trust)    = {n_img_misconf_strict}/{N} ({100*n_img_misconf_strict/N:.1f}%)")
print(f"  most common misconfigurations (share of {N} images):")
for did, c in dockle_id_imgcount.most_common(8):
    print(f"     {did:13s} {100*c/N:5.1f}%  {dockle_title.get(did)}")

# ============================================================ (4) SECRET FP
val = json.load(open(VAL))
by_cat = val["by_category"]
sample = val["sample_size"]
print()
print("=" * 70)
print(f"(4) SECRET FP CATEGORIES  (n={sample} hand-labeled; FP rate {val['fp_rate_pct']}%)")
print("-" * 70)
for name, c in by_cat:
    print(f"     {name:22s} {c:5d}  ({100*c/sample:.1f}%)")

# =====================================================================
# ============================  FIGURE  ===============================
# =====================================================================
fig, ax = plt.subplots(1, 3, figsize=(6.9, 1.95))

# --- panel (a): scanner divergence (per-image,CVE pooled) ---
labs = ["1 scanner", "2 scanners", "3 scanners"]
vals = list(ic_pct)
cols = [RED, ORANGE, GREEN]
b = ax[0].bar(labs, vals, color=cols)
figstyle.grid(ax[0])
for bb, p in zip(b, vals):
    ax[0].text(bb.get_x() + bb.get_width()/2, p + 1.5, f"{p:.0f}", ha="center", fontsize=6.3)
ax[0].set_ylabel("% of distinct CVEs")
ax[0].set_title("(a) Vuln-scanner agreement")
ax[0].set_ylim(0, max(vals) * 1.2)
ax[0].tick_params(axis="x", labelsize=6.8)

# --- panel (b): top OS distributions ---
top_os = os_counter.most_common(5)
names = [k for k, _ in top_os]
shares = [100 * v / N for _, v in top_os]
# append a "none" (distroless/lang-only) bar for completeness
names.append("None/distroless")
shares.append(100 * n_os_unknown / N)
oscol = [BLUE, ORANGE, GREEN, PURPLE, "#80b1d3", "#bbbbbb"][:len(names)]
order = np.argsort(shares)              # ascending -> largest on top in barh
names = [names[i] for i in order]; shares = [shares[i] for i in order]
oscol = [oscol[i] for i in order]
bb = ax[1].barh(names, shares, color=oscol)
figstyle.grid(ax[1], "x")
for rect, p in zip(bb, shares):
    ax[1].text(p + 1.0, rect.get_y() + rect.get_height()/2, f"{p:.0f}", va="center", fontsize=6.3)
ax[1].set_xlabel("% of images")
ax[1].set_title("(b) Base OS distribution")
ax[1].set_xlim(0, max(shares) * 1.18)
ax[1].tick_params(axis="y", labelsize=6.5)

# --- panel (c): secret FP categories ---
# group: drop TP/CANDIDATE from the FP-composition view, keep the named FP buckets
fp_buckets = [(n_, c_) for n_, c_ in by_cat if n_ not in ("TP", "CANDIDATE-credential")]
# nicer short labels
relabel = {
    "package-hash": "Package hash", "example/placeholder": "Example/placeholder",
    "binary/asset": "Binary/asset", "dependency-lock": "Dependency lock",
    "test-fixture": "Test fixture", "bare-hash": "Bare hash",
    "identifier/uuid": "Identifier/UUID",
}
fp_buckets.sort(key=lambda t: t[1])     # ascending for barh
cnames = [relabel.get(n_, n_) for n_, _ in fp_buckets]
cvals = [100 * c_ / sample for _, c_ in fp_buckets]
ccol = plt.cm.Blues(np.linspace(0.45, 0.92, len(cnames)))
bc = ax[2].barh(cnames, cvals, color=ccol)
figstyle.grid(ax[2], "x")
for rect, p in zip(bc, cvals):
    ax[2].text(p + 0.8, rect.get_y() + rect.get_height()/2, f"{p:.0f}", va="center", fontsize=6.3)
ax[2].set_xlabel("% of sampled detections")
ax[2].set_title("(c) Secret false-positive types")
ax[2].set_xlim(0, max(cvals) * 1.2)
ax[2].tick_params(axis="y", labelsize=6.0)

fig.tight_layout(w_pad=1.1)
fig.savefig(f"{OUT}/fig_extra.pdf", bbox_inches="tight", pad_inches=0.03)
plt.close(fig)
print()
print("wrote", f"{OUT}/fig_extra.pdf")
