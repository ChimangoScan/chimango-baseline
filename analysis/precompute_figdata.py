#!/usr/bin/env python3
"""
Precompute every figure array into a small JSON (analysis/figdata_baseline.json)
so the paper figures regenerate WITHOUT the multi-gigabyte reports database.

Why this exists
---------------
The per-image scanner reports live in a large SQLite database (reports table,
~9.7 GB, released on acceptance). The figure scripts (make_figs.py,
analyze_extra.py) need a handful of aggregate arrays from it (a per-image
vulnerability-count vector, severity totals, scanner-coverage counts, the
reachability breakdown from the jobs table, a scanner-agreement Venn over
(image, CVE) pairs, and the base-OS distribution). This one-off pass distills
all of those into a small JSON that is shipped with the artifact, so the
figures regenerate from JSON alone in the precomputed reproduction mode.

By default this distils ALL reports in the database, which is the canonical
corpus of N=2879 images used for the paper, so the precomputed figures match the
committed repro_baseline.json / secret_validation_baseline.json and the paper
exactly. An optional finished-at cutoff (CUTOFF below, disabled by default) is
available for the case where the live database has grown past the frozen corpus
and only reports up to a given instant should be included.

Run (only needed to regenerate the JSON from the database):
  BL_DB=/path/to/reports.db python3 analysis/precompute_figdata.py
Output: analysis/figdata_baseline.json (overridable via BL_OUT).
"""
import json
import os
import re
import sqlite3
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("BL_DB", "/path/to/reports.db")
OUT = os.environ.get("BL_OUT", _HERE)

# Optional finished-at cutoff: when > 0, include only reports finished before
# this instant (unix seconds). Disabled by default (0) so the canonical corpus is
# ALL reports in the database (N=2879), matching the paper. Set BL_CUTOFF_TS to a
# unix timestamp only to freeze the corpus if the live database has grown past it.
_DEFAULT_CUTOFF = 0.0
CUTOFF = float(os.environ.get("BL_CUTOFF_TS", _DEFAULT_CUTOFF))

VULN_SCANNERS = ("trivy", "grype", "osv")
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)
DISTRO_FAMILY = {
    "debian": "Debian", "ubuntu": "Ubuntu", "alpine": "Alpine",
    "centos": "CentOS", "rhel": "RHEL", "ol": "Oracle Linux",
    "oracle": "Oracle Linux", "rocky": "Rocky", "almalinux": "AlmaLinux",
    "alma": "AlmaLinux", "fedora": "Fedora", "amzn": "Amazon Linux",
    "amazonlinux": "Amazon Linux", "opensuse": "openSUSE", "sles": "SLES",
    "sled": "SLES", "arch": "Arch", "wolfi": "Wolfi", "chainguard": "Wolfi",
    "photon": "Photon", "mariner": "Mariner", "azurelinux": "Mariner",
}


def family_of(distro_tag):
    base = re.split(r"[-.]", distro_tag, 1)[0].lower()
    return DISTRO_FAMILY.get(base)


def main():
    con = sqlite3.connect("file:%s?immutable=1" % DB, uri=True)

    # --- per-image arrays (Fig A) ---
    vpi = []
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    cov = {}
    N = anyv = crit = high = secret = 0

    # --- scanner agreement / OS / misconfig (Fig extra) ---
    overall = {s: set() for s in VULN_SCANNERS}
    venn = {s: set() for s in VULN_SCANNERS}
    n_trio = 0
    img_share = Counter()
    n_img_vuln = 0
    percell_by1 = []
    percell_by2 = []
    percell_by3 = []
    img_os = []
    dockle_cnt = Counter()
    dockle_title = {}
    n_misc = n_misc_strict = n_dockle = 0
    trio_ok = Counter()

    for (img, rj, fa) in con.execute(
            "SELECT image, report_json, finished_at FROM reports"):
        if CUTOFF and fa is not None and fa >= CUTOFF:
            continue
        r = json.loads(rj)
        fs = r.get("findings") or []
        invs = r.get("invocations") or []
        N += 1
        ok = len([i for i in invs if i.get("status") == "ok"])
        cov[ok] = cov.get(ok, 0) + 1
        v = 0
        ic = ih = isec = False
        for f in fs:
            cat = f.get("category")
            if cat == "pkg-vuln":
                v += 1
                s = (f.get("severity") or "unknown").lower()
                if s in sev:
                    sev[s] += 1
                ic = ic or s == "critical"
                ih = ih or s == "high"
            elif cat == "secret":
                isec = True
        vpi.append(v)
        anyv += v > 0
        crit += ic
        high += ih
        secret += isec

        ok_vuln = {i.get("scanner") for i in invs
                   if i.get("scanner") in VULN_SCANNERS
                   and i.get("status") in ("ok", "ok-cached")}
        trio_ok[len(ok_vuln)] += 1
        trio_all = all(s in ok_vuln for s in VULN_SCANNERS)
        per = {s: set() for s in VULN_SCANNERS}
        distro = Counter()
        dids = set()
        dockle_ran = any(i.get("scanner") == "dockle"
                         and i.get("status") in ("ok", "ok-cached")
                         for i in invs)
        if dockle_ran:
            n_dockle += 1
        for f in fs:
            cat = f.get("category")
            sc = f.get("scanner")
            if cat == "pkg-vuln" and sc in VULN_SCANNERS:
                cves = f.get("cves") or []
                fid = f.get("id") or ""
                ids = {x.upper() for x in cves if CVE_RE.match(x or "")}
                if CVE_RE.match(fid):
                    ids.add(fid.upper())
                per[sc].update(ids)
                overall[sc].update(ids)
            elif cat == "sbom-component" and sc == "syft":
                pid = f.get("id") or ""
                m = re.search(r"distro=([a-zA-Z0-9._-]+)", pid)
                if m:
                    ff = family_of(m.group(1))
                    if ff:
                        distro[ff] += 1
            elif cat == "image-config" and sc == "dockle":
                dids.add(f.get("id"))
                dockle_title[f.get("id")] = f.get("title")
        if trio_all:
            n_trio += 1
            for s in VULN_SCANNERS:
                for cve in per[s]:
                    venn[s].add((img, cve))
        active = [s for s in VULN_SCANNERS if s in ok_vuln] or list(VULN_SCANNERS)
        union = set().union(*[per[s] for s in active]) if active else set()
        if union:
            n_img_vuln += 1
            b1 = b2 = b3 = 0
            for cve in union:
                k = sum(1 for s in active if cve in per[s])
                img_share[k] += 1
                if k == 1:
                    b1 += 1
                elif k == 2:
                    b2 += 1
                elif k >= 3:
                    b3 += 1
            tot = b1 + b2 + b3
            percell_by1.append(100 * b1 / tot)
            percell_by2.append(100 * b2 / tot)
            percell_by3.append(100 * b3 / tot)
        img_os.append(distro.most_common(1)[0][0] if distro else None)
        if dids:
            n_misc += 1
            if dids - {"CIS-DI-0005"}:
                n_misc_strict += 1
            for d in dids:
                dockle_cnt[d] += 1

    # --- reachability breakdown (Fig B), from the jobs table ---
    reach = {"scanned": N, "gone": 0, "arch": 0, "auth": 0,
             "format": 0, "infra": 0}
    for (st, e) in con.execute(
            "SELECT status, error FROM jobs "
            "WHERE status IN ('skipped','failed')"):
        el = (e or "").lower()
        if "no space" in el or "register layer" in el or "write /" in el:
            reach["infra"] += 1
        elif ("no matching manifest" in el or "platform" in el
              or "no child with platform" in el):
            reach["arch"] += 1
        elif any(s in el for s in ("denied", "unauthorized", "forbidden",
                                   "authentication required")):
            reach["auth"] += 1
        elif any(s in el for s in ("not found", "manifest unknown",
                                   "does not exist", "name unknown", "no such",
                                   "not known", "failed to resolve",
                                   "manifest for")):
            reach["gone"] += 1
        else:
            reach["format"] += 1
    con.close()

    T, G, O = venn["trivy"], venn["grype"], venn["osv"]
    venn_subsets = [len(T - G - O), len(G - T - O), len((T & G) - O),
                    len(O - T - G), len((T & O) - G), len((G & O) - T),
                    len(T & G & O)]
    os_counter = Counter(x for x in img_os if x).most_common()  # all families
    n_os_unknown = sum(1 for x in img_os if x is None)

    out = {
        "_meta": {
            "note": ("Precomputed figure arrays for the paper figures, distilled "
                     "from the reports database so figures regenerate with no "
                     "database. Distilled from all N=2879 reports (the canonical "
                     "corpus; no cutoff). Regenerate with: "
                     "BL_DB=/path/to/reports.db python3 "
                     "analysis/precompute_figdata.py"),
            "N": N,
            "cutoff_ts": CUTOFF,
        },
        "fig_panels3": {
            "N": N, "vpi_sorted": sorted(vpi), "sev": sev, "cov": cov,
            "anyvuln_pct": round(100 * anyv / N, 1),
            "crit_pct": round(100 * crit / N, 1),
            "high_pct": round(100 * high / N, 1),
            "secret_pct": round(100 * secret / N, 1),
        },
        "fig_reach": {"reach": reach},
        "fig_extra": {
            "venn_subsets": venn_subsets, "n_img_trio_all_ok": n_trio,
            "venn_card": {"trivy": len(T), "grype": len(G), "osv": len(O)},
            "os_counter": os_counter, "n_os_unknown": n_os_unknown,
            "dockle_top": dockle_cnt.most_common(8),
            "dockle_title": dockle_title, "n_img_dockle_ran": n_dockle,
            "n_img_misconf": n_misc, "n_img_misconf_strict": n_misc_strict,
        },
        "divergence": {
            "overall_card": {s: len(overall[s]) for s in VULN_SCANNERS},
            "img_share": dict(img_share), "n_img_with_vuln": n_img_vuln,
            "trio_ok": dict(trio_ok),
            "percell_mean": [
                round(sum(percell_by1) / len(percell_by1), 1) if percell_by1 else 0.0,
                round(sum(percell_by2) / len(percell_by2), 1) if percell_by2 else 0.0,
                round(sum(percell_by3) / len(percell_by3), 1) if percell_by3 else 0.0,
            ],
        },
    }
    path = os.path.join(OUT, "figdata_baseline.json")
    with open(path, "w") as fh:
        json.dump(out, fh)
    print("wrote %s  (N=%d, anyvuln=%s%%, crit=%s%%, secret=%s%%)" % (
        path, N, out["fig_panels3"]["anyvuln_pct"],
        out["fig_panels3"]["crit_pct"], out["fig_panels3"]["secret_pct"]))


if __name__ == "__main__":
    main()
