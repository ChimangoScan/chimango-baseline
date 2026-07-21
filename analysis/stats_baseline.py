#!/usr/bin/env python3
"""
Statistical companions to the headline prevalences: the two-proportion z-tests
against the high-exposure corpus, the pairwise scanner-agreement Jaccard
indices, unique-CVE (deduplicated) per-image counts, and the total finding
count. These are the paper numbers that repro_baseline.py / precompute_figdata.py
do not emit.

Run:
  BL_DB=/path/to/bl_snap.db python3 analysis/stats_baseline.py
Output: analysis/stats_baseline.json (overridable via BL_OUT).
"""
import json
import math
import os
import re
import sqlite3
import statistics

_HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("BL_DB", "/path/to/reports.db")
OUT = os.environ.get("BL_OUT", _HERE)

VULN_SCANNERS = ("trivy", "grype", "osv")
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.I)

# High-exposure corpus (companion paper): exact image counts over N=52,895.
COMPANION_N = 52895
COMPANION = {"critical": 49392, "high": 50534, "any": 50957}


def ztest(x1, n1, x2, n2):
    p1 = x1 / n1
    pool = (x1 + x2) / (n1 + n2)
    se = math.sqrt(pool * (1 - pool) * (1 / n1 + 1 / n2))
    z = (p1 - x2 / n2) / se
    p = math.erfc(abs(z) / math.sqrt(2))
    return {"x1": x1, "x2": x2, "z": round(z, 2), "p": round(p, 2),
            "p1": round(100 * p1, 1), "p2": round(100 * x2 / n2, 1)}


def main():
    con = sqlite3.connect("file:%s?immutable=1" % DB, uri=True)

    N = anyv = crit = high = 0
    uniq_cves = []
    venn = {s: set() for s in VULN_SCANNERS}
    for (img, rj) in con.execute("SELECT image, report_json FROM reports"):
        r = json.loads(rj)
        fs = r.get("findings") or []
        invs = r.get("invocations") or []
        N += 1
        ic = ih = iv = False
        per = {s: set() for s in VULN_SCANNERS}
        for f in fs:
            if f.get("category") != "pkg-vuln":
                continue
            iv = True
            s = (f.get("severity") or "").lower()
            ic = ic or s == "critical"
            ih = ih or s == "high"
            sc = f.get("scanner")
            if sc in VULN_SCANNERS:
                ids = {x.upper() for x in (f.get("cves") or [])
                       if CVE_RE.match(x or "")}
                fid = f.get("id") or ""
                if CVE_RE.match(fid):
                    ids.add(fid.upper())
                per[sc].update(ids)
        anyv += iv
        crit += ic
        high += ih
        uniq_cves.append(len(set().union(*per.values())))
        ok_vuln = {i.get("scanner") for i in invs
                   if i.get("scanner") in VULN_SCANNERS
                   and i.get("status") in ("ok", "ok-cached")}
        if all(s in ok_vuln for s in VULN_SCANNERS):
            for s in VULN_SCANNERS:
                for cve in per[s]:
                    venn[s].add((img, cve))

    (total_findings,) = con.execute(
        "SELECT sum(n_findings) FROM reports").fetchone()
    con.close()

    jacc = {}
    for a in VULN_SCANNERS:
        for b in VULN_SCANNERS:
            if a < b:
                u = len(venn[a] | venn[b])
                jacc["%s-%s" % (a, b)] = round(
                    len(venn[a] & venn[b]) / u, 2) if u else 0.0

    out = {
        "N": N,
        "total_findings": total_findings,
        "ztests": {
            "critical": ztest(crit, N, COMPANION["critical"], COMPANION_N),
            "high": ztest(high, N, COMPANION["high"], COMPANION_N),
            "any": ztest(anyv, N, COMPANION["any"], COMPANION_N),
        },
        "jaccard_image_cve": jacc,
        "jaccard_best_pair": max(jacc.items(), key=lambda kv: kv[1]),
        "unique_cves_per_image": {
            "median": statistics.median(uniq_cves),
            "mean": round(statistics.mean(uniq_cves), 1),
            "max": max(uniq_cves),
        },
    }
    path = os.path.join(OUT, "stats_baseline.json")
    with open(path, "w") as fh:
        json.dump(out, fh, indent=1)
    print("wrote %s" % path)
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
