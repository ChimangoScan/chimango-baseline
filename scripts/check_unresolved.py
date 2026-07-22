#!/usr/bin/env python3
"""
Registry check of the unresolved (no latest manifest) repositories.

Draws a seeded sample of the drawn repositories whose latest reference did not
resolve (the paper's 34.9%), queries the Docker Hub API for each, and records
whether the repository still exists, whether it has a latest tag, and its
last_updated timestamp. The committed analysis/unresolved_check.json is the
run of record for the paper's claim that the unresolved share is a property of
the default tag, not registry decay; re-running queries the live registry and
may differ as the registry changes.

Run:  BL_DB=/path/to/bl_snap.db python3 scripts/check_unresolved.py
"""
import json
import os
import random
import sqlite3
import time
import urllib.error
import urllib.request

DB = os.environ.get("BL_DB", "/path/to/reports.db")
OUT = os.environ.get("BL_OUT", os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "analysis"))
SEED = 20260721
N = 200

AUTHZ = ("denied", "unauthorized", "forbidden", "authentication required")
ARCH = ("no matching manifest", "platform")
GONE = ("not found", "manifest unknown", "does not exist", "name unknown",
        "no such", "not known", "failed to resolve", "manifest for")


def unresolved_repos():
    con = sqlite3.connect("file:%s?immutable=1" % DB, uri=True)
    repos = []
    for (tj, err) in con.execute(
            "SELECT target_json, error FROM jobs WHERE status='skipped'"):
        el = (err or "").lower()
        if any(s in el for s in ARCH) or any(s in el for s in AUTHZ):
            continue
        if any(s in el for s in GONE):
            m = json.loads(tj)["meta"]
            repos.append("%s/%s" % (m["repository_namespace"],
                                    m["repository_name"]))
    con.close()
    return repos


def fetch(url):
    req = urllib.request.Request(
        url, headers={"User-Agent": "reachability-check (research artifact)"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return None, None


def main():
    repos = unresolved_repos()
    sample = random.Random(SEED).sample(repos, min(N, len(repos)))
    rows = []
    for repo in sample:
        s, body = fetch("https://hub.docker.com/v2/repositories/%s/" % repo)
        row = {"repository": repo, "repo_http": s}
        if s == 200:
            row["last_updated"] = (body or {}).get("last_updated")
            t, _ = fetch(
                "https://hub.docker.com/v2/repositories/%s/tags/latest" % repo)
            row["latest_http"] = t
            row["verdict"] = ("alive-with-latest" if t == 200 else
                              "alive-no-latest" if t == 404 else "error")
        elif s == 404:
            row["verdict"] = "deleted"
        else:
            row["verdict"] = "error"
        rows.append(row)
        time.sleep(0.25)

    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    pushes = sorted(r["last_updated"] for r in rows
                    if r.get("last_updated"))
    out = {
        "checked_at": time.strftime("%Y-%m-%d"),
        "seed": SEED,
        "population_unresolved": len(repos),
        "sample_size": len(rows),
        "counts": counts,
        "median_last_updated": pushes[len(pushes) // 2] if pushes else None,
        "rows": rows,
    }
    path = os.path.join(OUT, "unresolved_check.json")
    with open(path, "w") as fh:
        json.dump(out, fh, indent=1)
    print("wrote %s" % path)
    print(counts, "median last_updated:", out["median_last_updated"])


if __name__ == "__main__":
    main()
