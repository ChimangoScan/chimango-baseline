#!/usr/bin/env python3
"""
Verify every number the paper asserts against the committed artifacts.

Each check recomputes a value from analysis/*.json (regenerable from the
released reports database) and compares it exactly with expected/paper_values.json.
Exit 0 only with zero FAIL.

Run:  python3 analysis/verify_values.py
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def load(name):
    return json.load(open(os.path.join(_HERE, name)))


def main():
    exp = json.load(open(os.path.join(_ROOT, "expected", "paper_values.json")))
    fd = load("figdata_baseline.json")
    rb = load("repro_baseline.json")
    st = load("stats_baseline.json")
    sv = load("secret_validation_baseline.json")

    p3 = fd["fig_panels3"]
    reach = fd["fig_reach"]["reach"]
    n_drawn = sum(reach.values())
    fe = fd["fig_extra"]
    dv = fd["divergence"]
    N = p3["N"]
    oc = dict(fe["os_counter"])
    dockle = dict(fe["dockle_top"])
    share_tot = sum(dv["img_share"].values())
    cov = {int(k): v for k, v in p3["cov"].items()}
    zr = rb["zerouali2019"]["ours_random"]
    uc = st["unique_cves_per_image"]

    got = {
        "n_drawn": n_drawn,
        "n_scanned": N,
        "pct_scanned": round(100 * reach["scanned"] / n_drawn, 1),
        "pct_gone": round(100 * reach["gone"] / n_drawn, 1),
        "pct_unpullable": round(100 * reach["format"] / n_drawn, 1),
        "n_unpullable": reach["format"],
        "pct_private": round(100 * reach["auth"] / n_drawn, 1),
        "pct_other_arch": round(100 * reach["arch"] / n_drawn, 1),
        "pct_dnf": round(100 * reach["dnf"] / n_drawn, 1),
        "pct_crit": p3["crit_pct"],
        "pct_high": p3["high_pct"],
        "pct_any": p3["anyvuln_pct"],
        "pct_secret_raw": p3["secret_pct"],
        "median_merged": int(zr["median_merged"]),
        "mean_merged": int(zr["mean_merged"]),
        "max_merged": zr["max_merged"],
        "median_distinct_cves": int(uc["median"]),
        "mean_distinct_cves": uc["mean"],
        "max_distinct_cves": uc["max"],
        "total_findings_millions": round(st["total_findings"] / 1e6, 1),
        "pct_six_scanners": round(100 * cov.get(6, 0) / N, 1),
        "pct_five_plus_scanners": round(
            100 * (cov.get(6, 0) + cov.get(5, 0)) / N, 1),
        "z_crit": st["ztests"]["critical"]["z"],
        "p_crit": st["ztests"]["critical"]["p"],
        "z_high": st["ztests"]["high"]["z"],
        "p_high": st["ztests"]["high"]["p"],
        "z_any": st["ztests"]["any"]["z"],
        "p_any": st["ztests"]["any"]["p"],
        "worst_severity_modal": rb["shu2017"]["ours_random"][
            "worst_severity_modal"],
        "n_official": rb["liu2020"]["ours_random"]["n_official"],
        "pct_eco_os": rb["wist2021"]["ours_random"]["eco_class_pct"]["os"],
        "pct_eco_lang": rb["wist2021"]["ours_random"]["eco_class_pct"]["lang"],
        "oldest_cve_year": rb["mills2023"]["ours_random"]["oldest_cve_year"],
        "jaccard_best_pair": st["jaccard_best_pair"][1],
        "pct_single_tool": round(100 * dv["img_share"]["1"] / share_tot, 1),
        "pct_all_three": round(100 * dv["img_share"]["3"] / share_tot, 1),
        "pct_os_identified": round(100 * (N - fe["n_os_unknown"]) / N, 1),
        "pct_debian": round(100 * oc["Debian"] / N, 1),
        "pct_alpine": round(100 * oc["Alpine"] / N, 1),
        "pct_ubuntu": round(100 * oc["Ubuntu"] / N, 1),
        "pct_distroless": round(100 * fe["n_os_unknown"] / N, 1),
        "pct_dockle_misconf": round(100 * fe["n_img_misconf"] / N, 1),
        "pct_nonroot_missing": round(100 * dockle["CIS-DI-0001"] / N, 1),
        "pct_healthcheck_missing": round(100 * dockle["CIS-DI-0006"] / N, 1),
        "pct_creds_env": round(100 * dockle["CIS-DI-0010"] / N, 1),
        "secret_sample_size": sv["sample_size"],
        "secret_true_positives": sv["true_positives"],
        "secret_fp_rate_pct": round(sv["fp_rate_pct"], 1),
        "secret_tp_rate_pct": sv["tp_rate_pct"],
    }

    n_pass = n_fail = 0
    for key, spec in exp.items():
        if key.startswith("_"):
            continue
        if key not in got:
            print("FAIL %-26s expected %-10s -> no computed value" % (
                key, spec["value"]))
            n_fail += 1
            continue
        ok = got[key] == spec["value"]
        n_pass += ok
        n_fail += not ok
        if not ok:
            print("FAIL %-26s expected %-10s got %-10s (%s)" % (
                key, spec["value"], got[key], spec["source"]))
    print("verify: %d pass, %d fail (skips listed in expected/_skip_note)"
          % (n_pass, n_fail))
    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
