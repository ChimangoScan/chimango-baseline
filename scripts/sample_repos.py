#!/usr/bin/env python3
"""Uniform random sample of Docker Hub repositories (the control group).

Draws N repositories from dockerhub_data.repositories_data (the crawl's MongoDB)
with $sample (server-side uniform sampling) and emits a repo:tag JSONL (one
:latest image per repo) in the format the scan pipeline consumes. The emitted
list IS the canonical record of the sample (reproducibility is by the list
itself, since $sample takes no seed).

Env:
  MONGO_URI    (default mongodb://127.0.0.1:27017)
  SAMPLE_N     number of repositories to draw (default 4800 -> ~2879 scanned
               after skips)
  OUT_PATH     (default data/random_sample.jsonl)
"""
import json
import os
from pymongo import MongoClient

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017")
N = int(os.environ.get("SAMPLE_N", "4800"))
OUT = os.environ.get("OUT_PATH", "data/random_sample.jsonl")


def pull_int(pc):
    """pull_count arrives as {high, low, unsigned} (a Mongo Long) or as an int."""
    if isinstance(pc, dict):
        return (int(pc.get("high", 0)) << 32) + int(pc.get("low", 0))
    try:
        return int(pc or 0)
    except (TypeError, ValueError):
        return 0


def main():
    cli = MongoClient(MONGO_URI)
    db = cli["dockerhub_data"]
    pipeline = [
        {"$sample": {"size": N}},
        {"$project": {"namespace": 1, "name": 1, "pull_count": 1, "_id": 0}},
    ]
    rows = db.repositories_data.aggregate(pipeline, allowDiskUse=True)
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    n = 0
    with open(OUT, "w") as f:
        for d in rows:
            ns = d.get("namespace") or ""
            nm = d.get("name") or ""
            if not nm:
                continue
            # repo:tag in the same format as the ranker (library -> name only)
            rt = nm if ns == "library" else (ns + "/" + nm if ns else nm)
            obj = {
                "repository_namespace": ns,
                "repository_name": nm,
                "tag_name": "latest",
                "image": rt + ":latest",
                "pull_count": pull_int(d.get("pull_count")),
            }
            f.write(json.dumps(obj, separators=(",", ":")) + "\n")
            n += 1
    cli.close()
    print("sample written: %d repositories -> %s" % (n, OUT))


if __name__ == "__main__":
    main()
