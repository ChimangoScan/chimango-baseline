#!/usr/bin/env python3
"""
Extract ALL TruffleHog secret detections from the baseline snapshot and draw a
reproducible random sample for ground-truth false-positive validation.

This mirrors the methodology of the companion high-exposure paper (manual
secret FP-validation) but runs over the *baseline* corpus snapshot (the reports
SQLite) and uses an explicit fixed-seed `random.Random(seed).sample`
over the full, materialised population (not reservoir sampling) so the sample is
exactly reproducible from the seed alone.

REPRODUCIBILITY
---------------
* DB        : the reports SQLite, table reports(image, report_json).
* Secret    : findings[] entries with category == "secret". Fields used:
                id / title  -> TruffleHog detector name (e.g. Box, AWS, PrivateKey)
                description -> matched / (sometimes) redacted value
                location    -> file path inside the image (may carry :linnumber)
                target_image-> image reference
                severity    -> finding severity
* Verified? : the finding schema has NO `verified`/`Verified` field (checked over
              every detection; see secret_validation_baseline.json
              -> "active_verification"). TruffleHog ran in *unverified* mode, so
              we have no live-verification signal; this is recorded explicitly and
              the validation is purely manual/heuristic ground truth.
* Seed      : SEED = 20260522, sampler = random.Random(SEED).sample(population, n).
* n         : N_SAMPLE = 1100 (uniform random, same size as the companion paper:
              95% CI, +-3% on a proportion; or the whole population if smaller).

SECRET REDACTION
----------------
The raw `description` in this DB is NOT guaranteed to be redacted (some detectors
store the live matched value, e.g. AWS AKIA... keys). We therefore NEVER persist
the raw value. Every record carries:
    value_redacted : first 6 + last 3 chars with the middle masked (PEM blocks and
                     <=10-char values are masked further),
    value_sha256   : sha256 of the raw value (lets a reviewer confirm a value
                     without the value ever leaving the pipeline),
    value_len / value_entropy / value_distinct : shape features for triage.
The raw value is kept ONLY in memory long enough to derive those features.

Outputs (all under $BL_OUT, default: this script's directory):
  secret_dist_baseline.json    population stats: totals, by-detector, by-location.
  secret_sample_baseline.jsonl  the seeded random sample, one JSON object/line.
DB path is overridable via $BL_DB (the reports SQLite is released with the artifact).
"""
import os, sqlite3, json, re, random, hashlib, math
from collections import Counter

# BL_DB / BL_OUT overridable for the artifact (DB released with the artifact).
DB = os.environ.get("BL_DB", "/path/to/reports.db")
OUT = os.environ.get("BL_OUT", os.path.dirname(os.path.abspath(__file__)))
SEED = 20260522
N_SAMPLE = 1100


def entropy(v: str) -> float:
    if not v:
        return 0.0
    c = Counter(v)
    n = len(v)
    return -sum((k / n) * math.log2(k / n) for k in c.values())


def redact(v: str) -> str:
    """Mask the value so the secret never leaks but its shape stays inspectable."""
    v = v or ""
    if "BEGIN" in v and "PRIVATE" in v:
        return f"<PEM-PRIVATE-KEY len={len(v)}>"
    if "BEGIN" in v:
        return f"<PEM-BLOCK len={len(v)}>"
    if len(v) <= 10:
        return (v[:2] + "***") if v else "<empty>"
    return f"{v[:6]}***{v[-3:]}"


def locpat(loc: str) -> str:
    """Coarse location bucket for the population distribution (descriptive only)."""
    l = loc.lower()
    if l.endswith(".md5sums") or "/var/lib/dpkg/" in l or "/var/lib/apt/" in l or "/var/cache/" in l:
        return "OS pkg metadata/checksums"
    if re.search(r"(node_modules|site-packages|dist-packages|/pkg/mod/|\.cargo/|/gems/|vendor/|/registry/)", l):
        return "dependency / vendored"
    if re.search(r"(test|spec|fixture|mock|example|sample|demo|testdata)", l):
        return "test/example/sample path"
    if re.search(r"\.(so|so\.\d+|a|o|dll|bin|jar|whl|pyc|mo|po|sqlite|wasm|pak|dat|lz4)(\b|$|:)", l):
        return "binary/asset"
    if re.search(r"(/\.env|/\.aws/|/credentials|id_rsa|id_dsa|id_ecdsa|/\.ssh/|\.pgpass|\.netrc|production\.json|appsettings.*production)", l):
        return "credential-bearing path"
    if re.search(r"\.(md|txt|rst|html?|adoc)(\b|$|:)", l):
        return "doc/text file"
    if l.endswith((".pem", ".key", ".crt", ".pub", ".ppk")) or ":" in l and re.search(r"\.(pem|key|crt|pub|ppk):", l):
        return "key/cert file"
    return "other"


def main():
    os.makedirs(OUT, exist_ok=True)
    con = sqlite3.connect(DB)
    population = []
    det = Counter()
    locp = Counter()
    n_img = 0
    for (img, rj) in con.execute("SELECT image, report_json FROM reports"):
        try:
            j = json.loads(rj)
        except Exception:
            continue
        secs = [f for f in (j.get("findings") or []) if f.get("category") == "secret"]
        if not secs:
            continue
        n_img += 1
        for f in secs:
            raw = f.get("description") or ""
            det[f.get("id", "?")] += 1
            locp[locpat(f.get("location", ""))] += 1
            population.append({
                "image": (f.get("target_image") or img),
                "detector": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "location": f.get("location", ""),
                "value_redacted": redact(raw),
                "value_sha256": hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16],
                "value_len": len(raw),
                "value_entropy": round(entropy(raw), 3),
                "value_distinct": len(set(raw)),
                "value_is_pem": ("BEGIN" in raw),
            })
    con.close()

    total = len(population)
    # deterministic random sample
    n = min(N_SAMPLE, total)
    rng = random.Random(SEED)
    sample = rng.sample(population, n)

    json.dump({
        "db": DB,
        "total_secret_detections": total,
        "images_with_secret": n_img,
        "distinct_detectors": len(det),
        "by_detector": det.most_common(),
        "by_location_bucket": locp.most_common(),
    }, open(f"{OUT}/secret_dist_baseline.json", "w"), indent=1)

    with open(f"{OUT}/secret_sample_baseline.jsonl", "w") as fh:
        # header line records provenance so the file is self-describing
        fh.write(json.dumps({
            "_meta": True, "db": DB, "seed": SEED, "sampler": "random.Random(seed).sample",
            "population": total, "sample_size": n,
            "fields": "image,detector,title,severity,location,value_redacted,value_sha256,value_len,value_entropy,value_distinct,value_is_pem",
        }) + "\n")
        for r in sample:
            fh.write(json.dumps(r, sort_keys=True) + "\n")

    print(f"DONE population={total:,} images={n_img:,} sample={n} seed={SEED}")
    print("top detectors:", det.most_common(8))
    print("location buckets:", locp.most_common())


if __name__ == "__main__":
    main()
