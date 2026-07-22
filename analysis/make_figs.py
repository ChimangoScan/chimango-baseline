#!/usr/bin/env python3
"""Compact, publication-style figures for the random-sample baseline short paper.
Two original figures plus a reproduction panel: a per-image overview (3 panels),
a reachability breakdown that is unique to the random sample, and a reproduction
of prior analyses on the random sample.

Data sources, in order of preference:
  * If the reports database exists (BL_DB points at an existing file), the
    per-image and reachability panels are computed from it in one streaming pass
    (full mode).
  * Otherwise the shipped precomputed arrays (analysis/figdata_baseline.json,
    produced by analysis/precompute_figdata.py) are used, so every figure
    regenerates with NO database and no network (precomputed mode, the default).
The reproduction panel always reads the committed analysis/repro_baseline.json.
"""
import json, os, sqlite3
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import figstyle

# Overridable for the artifact: BL_DB = reports SQLite (released with the artifact),
# BL_FIGS = output directory for the PDFs (default: ../figures relative here).
_HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("BL_DB", "/path/to/reports.db")
OUT = os.environ.get("BL_FIGS", os.path.join(os.path.dirname(_HERE), "figures"))
FIGDATA = os.path.join(_HERE, "figdata_baseline.json")
figstyle.apply()
BLUE, RED, GREEN = "#4575b4", "#b2182b", "#1a9850"
SEVCOL = [RED, "#f46d43", "#fdae61", "#fee090"]


os.makedirs(OUT, exist_ok=True)


def save(fig, name):
    fig.savefig(f"{OUT}/{name}.pdf", bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)
    print("wrote", name)


def from_db():
    """One streaming pass over the reports + jobs tables (full mode)."""
    vpi = []
    sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    cov = {}
    n = anyv = crit = high = secret = 0
    c = sqlite3.connect(f"file:{DB}?immutable=1", uri=True)
    for (rj,) in c.execute("SELECT report_json FROM reports"):
        r = json.loads(rj); fs = r.get("findings") or []; n += 1
        ok = len([i for i in (r.get("invocations") or []) if i.get("status") == "ok"])
        cov[ok] = cov.get(ok, 0) + 1
        v = 0; ic = ih = isec = False
        for f in fs:
            cat = f.get("category")
            if cat == "pkg-vuln":
                v += 1
                s = (f.get("severity") or "unknown").lower()
                if s in sev: sev[s] += 1
                ic = ic or s == "critical"; ih = ih or s == "high"
            elif cat == "secret":
                isec = True
        vpi.append(v); anyv += v > 0; crit += ic; high += ih; secret += isec
    N = n
    reach = {"scanned": N, "gone": 0, "arch": 0, "auth": 0, "format": 0, "dnf": 0}
    for (st, e) in c.execute("SELECT status, error FROM jobs WHERE status IN ('skipped','failed')"):
        el = (e or "").lower()
        if st == "failed": reach["dnf"] += 1
        elif "no matching manifest" in el or "platform" in el or "no child with platform" in el: reach["arch"] += 1
        elif any(s in el for s in ("denied", "unauthorized", "forbidden", "authentication required")): reach["auth"] += 1
        elif any(s in el for s in ("not found", "manifest unknown", "does not exist", "name unknown", "no such", "not known", "failed to resolve", "manifest for")): reach["gone"] += 1
        else: reach["format"] += 1
    c.close()
    return (N, vpi, sev, cov, reach,
            100*anyv/N, 100*crit/N, 100*high/N, 100*secret/N)


def from_precomputed():
    """Read the shipped precomputed arrays (precomputed mode, no database)."""
    d = json.load(open(FIGDATA))
    p = d["fig_panels3"]
    cov = {int(k): v for k, v in p["cov"].items()}
    return (p["N"], p["vpi_sorted"], p["sev"], cov, d["fig_reach"]["reach"],
            p["anyvuln_pct"], p["crit_pct"], p["high_pct"], p["secret_pct"])


# choose the data source: real DB if present, else the precomputed JSON
if os.path.exists(DB):
    N, vpi, sev, cov, reach, anyv_pct, crit_pct, high_pct, secret_pct = from_db()
    print("source: reports database", DB)
else:
    N, vpi, sev, cov, reach, anyv_pct, crit_pct, high_pct, secret_pct = from_precomputed()
    print("source: precomputed", FIGDATA, "(no database)")

# === Fig A: per-image overview, three panels ===
vpi = np.sort(np.array(vpi)); cdf = np.arange(1, len(vpi)+1)/len(vpi)*100
med = int(np.median(vpi))
fig, ax = plt.subplots(1, 3, figsize=(6.9, 1.4))
ax[0].plot(np.maximum(vpi, 0.5), cdf, color=BLUE); ax[0].set_xscale("log")
figstyle.grid(ax[0]); ax[0].axvline(med, ls="--", color="#999", lw=0.8)
ax[0].text(med*1.25, 7, f"median {med}", fontsize=6.3, color="#666")
ax[0].set_xlabel("Pkg. vulnerabilities/image"); ax[0].set_ylabel("Cumulative % of images")
ax[0].set_title("(a) Vulnerabilities per image"); ax[0].set_ylim(0, 100)
labs = ["Crit.", "High", "Med.", "Low"]; vals = [sev[k] for k in ("critical", "high", "medium", "low")]
pct = [100*x/sum(vals) for x in vals]
b = ax[1].bar(labs, pct, color=SEVCOL); figstyle.grid(ax[1])
for bb, p in zip(b, pct): ax[1].text(bb.get_x()+bb.get_width()/2, p+0.8, f"{p:.0f}", ha="center", fontsize=6.3)
ax[1].set_ylabel("% of pkg-vuln findings"); ax[1].set_title("(b) Severity mix"); ax[1].set_ylim(0, max(pct)*1.2)
cl = ["6", "5", "0-4"]; cv = [cov.get(6, 0), cov.get(5, 0), sum(cov.get(k, 0) for k in range(0, 5))]
cvp = [100*x/N for x in cv]
b = ax[2].bar(cl, cvp, color=[GREEN, "#fdae61", RED]); figstyle.grid(ax[2])
for bb, p in zip(b, cvp): ax[2].text(bb.get_x()+bb.get_width()/2, p+1.5, f"{p:.0f}", ha="center", fontsize=6.3)
ax[2].set_ylabel("% of images"); ax[2].set_xlabel("scanners completed")
ax[2].set_title("(c) Scanner completion"); ax[2].set_ylim(0, 100)
fig.tight_layout(w_pad=1.1); save(fig, "fig_panels3")

# === Fig B: reachability of a uniform random draw (unique to this study) ===
# Outcomes of every drawn repository (infra disk failures re-queued, excluded).
order = [("Scanned", "scanned", GREEN), ("No latest", "gone", RED),
         ("Unpullable", "format", "#8073ac"), ("Denied", "auth", "#fdae61"),
         ("Other arch.", "arch", "#80b1d3"), ("DNF", "dnf", "#999999")]
tot = sum(reach[k] for _, k, _ in order)
fig, ax = plt.subplots(figsize=(6.9, 0.95))
left = 0.0
for label, key, col in order:
    w = 100*reach[key]/tot
    ax.barh(0, w, left=left, color=col, edgecolor="white", linewidth=0.6)
    if w > 3:
        ax.text(left+w/2, 0, f"{label}\n{w:.1f}%", ha="center", va="center",
                fontsize=6.4, color="white" if key in ("scanned", "gone") else "#222")
    left += w
ax.set_xlim(0, 100); ax.set_ylim(-0.5, 0.5); ax.axis("off")
ax.set_title("Outcome of a uniform random draw of the Docker Hub namespace", fontsize=8.5, pad=3)
save(fig, "fig_reach")

# === Fig C: reproduction of prior analyses on the random sample (5 panels, 2 rows) ===
R = json.load(open(os.path.join(_HERE, "repro_baseline.json"))); FD = R["figure_data"]
fig = plt.figure(figsize=(6.9, 2.5))
gs = fig.add_gridspec(2, 6)
ax = [fig.add_subplot(gs[0, 0:2]), fig.add_subplot(gs[0, 2:4]),
      fig.add_subplot(gs[0, 4:6]), fig.add_subplot(gs[1, 0:3]),
      fig.add_subplot(gs[1, 3:6])]
yrs = FD["cve_by_year"]["years"]; cnts = FD["cve_by_year"]["counts"]
ax[0].bar(yrs, cnts, color=BLUE, width=0.9); figstyle.grid(ax[0])
ax[0].set_xlabel("CVE identifier year"); ax[0].set_ylabel("Distinct CVEs")
ax[0].set_title("(a) CVEs by year"); ax[0].set_xticks([1999, 2012, 2026]); ax[0].set_xlim(1997.5, 2027.5)
ep = FD["ecosystem_split"]["ours_pct"]
b = ax[1].bar(["OS", "Lang.", "Other"], ep, color=[BLUE, "#f46d43", "#cccccc"]); figstyle.grid(ax[1])
for bb, p in zip(b, ep): ax[1].text(bb.get_x()+bb.get_width()/2, p+1.5, f"{p:.0f}", ha="center", fontsize=6.3)
ax[1].set_ylabel("% of severe findings"); ax[1].set_title("(b) Severe findings by ecosystem"); ax[1].set_ylim(0, 100)
top = R["shu2017"]["ours_random"]["top10_packages"][:6][::-1]
ax[2].barh([p["package"] for p in top], [p["pct_corpus"] for p in top], color=GREEN)
figstyle.grid(ax[2], "x")
ax[2].set_xlabel("% of images"); ax[2].set_title("(c) Top vulnerable packages"); ax[2].set_xlim(0, 100)
ax[2].tick_params(axis="y", labelsize=6.5)
studies = ["Shu et al. 2017", "Liu et al. 2020", "Dr. Docker 2025"]
reported = [80, 64, 93.7]; highexp = [93.4, 95.6, 96.3]; rnd = [94.4, 96.6, 96.8]
yy = np.arange(len(studies)); hh = 0.26
ax[3].barh(yy+hh, reported, hh, color="#bbbbbb", label="reported")
ax[3].barh(yy, highexp, hh, color="#f46d43", label="highest-exposure")
ax[3].barh(yy-hh, rnd, hh, color=BLUE, label="random (ours)")
ax[3].set_yticks(yy); ax[3].set_yticklabels(studies, fontsize=6.5)
ax[3].set_xlim(0, 100); ax[3].set_xlabel("% of images with vulnerability")
ax[3].set_title("(d) Prevalence vs. prior reports"); figstyle.grid(ax[3], "x")
ax[3].legend(fontsize=5.8, loc="lower left", framealpha=0.9)
labs2 = ["Shu et al.\n2017", "Zerouali et al.\n2019", "Highest-exp.\n2026", "Random\n2026"]
med2 = [158, 601, 885, 947]
b2 = ax[4].bar(labs2, med2, color=["#bbbbbb", "#bbbbbb", "#f46d43", BLUE]); figstyle.grid(ax[4])
for bb, m in zip(b2, med2): ax[4].text(bb.get_x()+bb.get_width()/2, m+18, str(m), ha="center", fontsize=6.3)
ax[4].set_ylabel("Median vulns/image"); ax[4].set_title("(e) Median vulnerabilities per image over a decade")
ax[4].set_ylim(0, 1080); ax[4].tick_params(axis="x", labelsize=6.0)
fig.tight_layout(w_pad=1.0, h_pad=1.4); save(fig, "fig_repro")

print(f"N={N} anyvuln={anyv_pct:.1f}% crit={crit_pct:.1f}% high={high_pct:.1f}% "
      f"secret={secret_pct:.1f}% median={med}")
print("reach:", reach, "| scanned%=", round(100*reach['scanned']/sum(reach[k] for _,k,_ in order), 1),
      "gone%=", round(100*reach['gone']/sum(reach[k] for _,k,_ in order), 1))
