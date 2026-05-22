#!/usr/bin/env python3
"""Compact, publication-style figures for the random-sample control short paper.
Shares the companion paper's figstyle. Two ORIGINAL figures only (no figure is
reused from the companion): a per-image overview (3 panels) and a reachability
breakdown that is unique to the random sample (the companion has no decay)."""
import json, os, sqlite3
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import figstyle

# Overridable for the artifact: BL_DB = reports SQLite (released on acceptance),
# BL_FIGS = output directory for the PDFs (default: ./figures).
DB = os.environ.get("BL_DB", "/mnt/win_ssd/bl_snap.db")
OUT = os.environ.get("BL_FIGS", "figures")
figstyle.apply()
BLUE, RED, GREEN = "#4575b4", "#b2182b", "#1a9850"
SEVCOL = [RED, "#f46d43", "#fdae61", "#fee090"]


os.makedirs(OUT, exist_ok=True)


def save(fig, name):
    fig.savefig(f"{OUT}/{name}.pdf", bbox_inches="tight", pad_inches=0.03)
    plt.close(fig)
    print("wrote", name)


# --- pass 1: per-image stats from the scanned reports ---
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

# --- pass 2: reachability outcome of every drawn repository (from jobs) ---
reach = {"scanned": 0, "gone": 0, "arch": 0, "auth": 0, "format": 0, "infra": 0}
reach["scanned"] = N
for (st, e) in c.execute("SELECT status, error FROM jobs WHERE status IN ('skipped','failed')"):
    el = (e or "").lower()
    if "no space" in el or "register layer" in el or "write /" in el: reach["infra"] += 1
    elif "no matching manifest" in el or "platform" in el or "no child with platform" in el: reach["arch"] += 1
    elif any(s in el for s in ("denied", "unauthorized", "forbidden", "authentication required")): reach["auth"] += 1
    elif any(s in el for s in ("not found", "manifest unknown", "does not exist", "name unknown", "no such", "not known", "failed to resolve", "manifest for")): reach["gone"] += 1
    else: reach["format"] += 1
c.close()

# === Fig A: per-image overview, three panels ===
vpi = np.sort(np.array(vpi)); cdf = np.arange(1, len(vpi)+1)/len(vpi)*100
med = int(np.median(vpi))
fig, ax = plt.subplots(1, 3, figsize=(6.9, 1.95))
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
ax[2].set_title("(c) Scanner coverage"); ax[2].set_ylim(0, 100)
fig.tight_layout(w_pad=1.1); save(fig, "fig_panels3")

# === Fig B: reachability of a uniform random draw (unique to this study) ===
# Outcomes of every drawn repository (infra disk failures re-queued, excluded).
order = [("Scanned", "scanned", GREEN), ("Gone (404)", "gone", RED),
         ("Non-image (OCI)", "format", "#8073ac"), ("Private", "auth", "#fdae61"),
         ("Other arch.", "arch", "#80b1d3")]
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

# === Fig C: reproduction of prior analyses on the random sample (3 panels) ===
_HERE = os.path.dirname(os.path.abspath(__file__))
R = json.load(open(os.path.join(_HERE, "repro_baseline.json"))); FD = R["figure_data"]
fig, ax = plt.subplots(1, 3, figsize=(6.9, 1.95))
yrs = FD["cve_by_year"]["years"]; cnts = FD["cve_by_year"]["counts"]
ax[0].bar(yrs, cnts, color=BLUE, width=0.9); figstyle.grid(ax[0])
ax[0].set_xlabel("CVE identifier year"); ax[0].set_ylabel("Distinct CVEs")
ax[0].set_title("(a) CVEs by year"); ax[0].set_xticks([1999, 2012, 2026]); ax[0].set_xlim(1997.5, 2027.5)
ep = FD["ecosystem_split"]["ours_pct"]
b = ax[1].bar(["OS", "Lang.", "Other"], ep, color=[BLUE, "#f46d43", "#cccccc"]); figstyle.grid(ax[1])
for bb, p in zip(b, ep): ax[1].text(bb.get_x()+bb.get_width()/2, p+1.5, f"{p:.0f}", ha="center", fontsize=6.3)
ax[1].set_ylabel("% of severe findings"); ax[1].set_title("(b) Severe by ecosystem"); ax[1].set_ylim(0, 100)
top = R["shu2017"]["ours_random"]["top10_packages"][:6][::-1]
ax[2].barh([p["package"] for p in top], [p["pct_corpus"] for p in top], color=GREEN)
figstyle.grid(ax[2], "x")
ax[2].set_xlabel("% of images"); ax[2].set_title("(c) Top vulnerable packages"); ax[2].set_xlim(0, 100)
ax[2].tick_params(axis="y", labelsize=6.5)
fig.tight_layout(w_pad=1.1); save(fig, "fig_repro")

print(f"N={N} anyvuln={100*anyv/N:.1f}% crit={100*crit/N:.1f}% high={100*high/N:.1f}% "
      f"secret={100*secret/N:.1f}% median={med}")
print("reach:", reach, "| scanned%=", round(100*reach['scanned']/sum(reach[k] for _,k,_ in order), 1),
      "gone%=", round(100*reach['gone']/sum(reach[k] for _,k,_ in order), 1))
