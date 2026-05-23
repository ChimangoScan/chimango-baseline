#!/usr/bin/env python3
"""Minimal, self-contained check: the shipped data parses and the committed
outputs match the paper's headline numbers. No database, no network, no
third-party packages (standard library only). Mirrors the README "Minimal test".
"""
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)


def _load(rel):
    return json.load(open(os.path.join(_ROOT, rel)))


def main():
    rows = [json.loads(line)
            for line in open(os.path.join(_ROOT, "data/random_sample.jsonl"))]
    assert len(rows) == 4800, len(rows)
    need = {"repository_namespace", "repository_name", "tag_name", "image"}
    assert all(need <= r.keys() for r in rows)
    print("OK: random_sample.jsonl has", len(rows), "repositories")

    R = _load("analysis/repro_baseline.json")
    assert R["meta"]["n_reports"] == 2879
    assert R["drdocker2025"]["ours_random"]["pct_with_known_vuln"] == 96.8
    assert R["liu2020"]["ours_random"]["n_official"] == 0
    V = _load("analysis/secret_validation_baseline.json")
    assert V["true_positives"] == 5 and V["sample_size"] == 1100
    F = _load("analysis/figdata_baseline.json")
    assert F["fig_panels3"]["N"] == 2879
    print("OK: committed outputs match the paper (N=2879, 96.8% any-vuln, "
          "0 official, 5/1100 secret TPs)")


if __name__ == "__main__":
    main()
