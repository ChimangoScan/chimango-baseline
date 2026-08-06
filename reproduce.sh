#!/usr/bin/env bash
#
# Reproduction driver for the uniform-random-sample baseline artifact.
#
#   ./reproduce.sh precomputed
#       Regenerate every paper figure and re-check the headline numbers from the
#       SHIPPED data only. No external database, no network, no Docker. This is
#       the fast, self-contained path used for artifact evaluation.
#
#   ./reproduce.sh analyze [--db PATH]
#       Recompute the analysis outputs and figures from a reports SQLite. If no
#       path is given, download and checksum-verify the released canonical DB.
#
#   ./reproduce.sh scan [--scanners-dir PATH]
#       Execute the separate six-scanner pipeline with its prepared config.
#       This command never falls back to the released database.
#
#   ./reproduce.sh dataset [DIR]
#       Download the released reports database (bl_snap.db.zst, 226 MB) from
#       the GitHub release into DIR (default: data/), verify both SHA-256
#       checksums, and decompress it (needs ~11 GB free in DIR).
#
#   ./reproduce.sh verify
#       Compare every number the paper asserts (expected/paper_values.json)
#       exactly against the committed analysis outputs. Exit 0 only on 0 FAIL.
#
# Environment overrides:
#   PYTHON   python interpreter (default: python3)
#   BL_DB    path to the reports SQLite (analyze mode; overridden by --db)
#   BL_FIGS  output directory for figures (default: ./figures)
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
if [ -z "${PYTHON:-}" ] && [ -x "$HERE/.venv/bin/python" ]; then
    PYTHON="$HERE/.venv/bin/python"
else
    PYTHON="${PYTHON:-python3}"
fi
export BL_FIGS="${BL_FIGS:-$HERE/figures}"

log() { printf '\n=== %s ===\n' "$*"; }

# Lists the figures THIS run produced, given a timestamp taken just before the
# generators ran. Listing the whole folder instead would report a PDF left behind by
# an older version of the artifact as if it had just been regenerated, which is how a
# figure the paper no longer contains kept showing up in the output.
figs_written() {
    find "$BL_FIGS" -maxdepth 1 -name '*.pdf' -newermt "$1" | sort
}

usage() {
    sed -n "2,31p" "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

# --------------------------------------------------------------------------
precomputed() {
    log "PRECOMPUTED reproduction (no database, no network)"
    mkdir -p "$BL_FIGS"

    log "1/3  Sanity-check the shipped data and committed outputs"
    "$PYTHON" - <<'PY'
import json
rows = [json.loads(l) for l in open("data/random_sample.jsonl")]
assert len(rows) == 4800, len(rows)
need = {"repository_namespace", "repository_name", "tag_name", "image"}
assert all(need <= r.keys() for r in rows)
R = json.load(open("analysis/repro_baseline.json"))
assert R["meta"]["n_reports"] == 2879
assert R["drdocker2025"]["ours_random"]["pct_with_known_vuln"] == 96.8
assert R["liu2020"]["ours_random"]["n_official"] == 0
V = json.load(open("analysis/secret_validation_baseline.json"))
assert V["true_positives"] == 5 and V["sample_size"] == 1100
F = json.load(open("analysis/figdata_baseline.json"))
assert F["fig_panels3"]["N"] == 2879
print("OK: random_sample.jsonl=4800 rows; repro N=2879, 96.8%% any-vuln, "
      "0 official; secret TPs=5/1100; figdata N=2879")
PY

    log "2/4  Regenerate the figures from the precomputed data"
    # With no BL_DB pointing at an existing file, both scripts read the shipped
    # analysis/figdata_baseline.json and analysis/repro_baseline.json.
    unset BL_DB || true
    local since; since=$(date -d '1 second ago' +%Y-%m-%dT%H:%M:%S)
    "$PYTHON" analysis/make_figs.py
    "$PYTHON" analysis/analyze_extra.py

    log "3/4  Figures written"
    figs_written "$since"

    log "4/4  Verify the paper's numbers against the committed outputs"
    "$PYTHON" analysis/verify_values.py
    echo
    echo "Precomputed reproduction complete. PDFs are in: $BL_FIGS"
}

# --------------------------------------------------------------------------
verify() {
    log "VERIFY paper values against committed outputs"
    "$PYTHON" analysis/verify_values.py
}

# --------------------------------------------------------------------------
DATASET_URL="https://github.com/ChimangoScan/chimango-baseline/releases/download/dataset-v1/bl_snap.db.zst"
SHA_ZST="8fb43ecd312483d0a1b578c8c7685546a2197bc0d90577e2b7f8d19d77eeb580"
SHA_DB="70e43470cd877999a236be578e733233b8d3a9a382f220e7804b98ad46c58ab6"

dataset() {
    local DIR="${1:-data}"
    mkdir -p "$DIR"
    local DB="$DIR/bl_snap.db" ZST="$DIR/bl_snap.db.zst"
    if [ -f "$DB" ] && echo "$SHA_DB  $DB" | sha256sum -c --quiet -; then
        log "Dataset already present and verified: $DB" >&2
        echo "$DB"; return 0
    fi
    local FREE_GB; FREE_GB=$(df -BG --output=avail "$DIR" | tail -1 | tr -dc 0-9)
    [ "$FREE_GB" -ge 11 ] || { echo "need ~11 GB free in $DIR (have ${FREE_GB} GB)" >&2; exit 1; }
    if [ ! -f "$ZST" ] || ! echo "$SHA_ZST  $ZST" | sha256sum -c --quiet -; then
        log "Downloading the reports database (226 MB)" >&2
        "$PYTHON" - "$DATASET_URL" "$ZST" <<'PY'
import shutil
import sys
import urllib.request

request = urllib.request.Request(sys.argv[1], headers={"User-Agent": "chimango-baseline-artifact"})
with urllib.request.urlopen(request) as response, open(sys.argv[2], "wb") as output:
    shutil.copyfileobj(response, output, length=1024 * 1024)
PY
        echo "$SHA_ZST  $ZST" | sha256sum -c - || { echo "checksum mismatch: $ZST" >&2; exit 1; }
    fi
    log "Decompressing to $DB (10.3 GB)" >&2
    "$PYTHON" - "$ZST" "$DB" <<'PY'
import sys
import zstandard

with open(sys.argv[1], "rb") as source, open(sys.argv[2], "wb") as target:
    zstandard.ZstdDecompressor().copy_stream(source, target)
PY
    echo "$SHA_DB  $DB" | sha256sum -c - || { echo "checksum mismatch: $DB" >&2; exit 1; }
    log "Dataset ready: $DB" >&2
    echo "$DB"
}

# --------------------------------------------------------------------------
analyze() {
    local DB=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --db) DB="$2"; shift 2 ;;
            *) echo "unknown option for analyze: $1" >&2; usage 2 ;;
        esac
    done

    DB="${DB:-${BL_DB:-}}"
    if [ -z "$DB" ]; then
        DB="$(dataset data | tail -1)"
    fi
    [ -f "$DB" ] || { echo "reports database not found: $DB" >&2; exit 1; }

    # Re-verify the database against its published checksum immediately before reading it,
    # even when it was just decompressed. The check inside dataset() runs while the freshly
    # written file is still in the page cache, so it can pass on a machine whose storage
    # later returns different bytes; that showed up once as a JSONDecodeError deep inside the
    # analysis, which tells the evaluator nothing. ~40 s against a 4-7 min analysis.
    if [ "$DB" = "data/bl_snap.db" ] || [ "$(basename "$DB")" = "bl_snap.db" ]; then
        log "Verifying $DB against the published checksum"
        if ! echo "$SHA_DB  $DB" | sha256sum -c --quiet -; then
            echo "" >&2
            echo "ERROR: $DB does not match the published SHA-256." >&2
            echo "The file on disk is not the released dataset: the download or the" >&2
            echo "decompression produced different bytes, or the storage is returning" >&2
            echo "them corrupted. Delete it and run this command again:" >&2
            echo "    rm -f $DB && ./reproduce.sh analyze" >&2
            echo "If it fails a second time, check the disk before trusting any result." >&2
            exit 1
        fi
    fi

    log "1/2  Recompute analysis outputs from $DB"
    BL_DB="$DB" BL_OUT=analysis "$PYTHON" analysis/repro_baseline.py
    BL_DB="$DB" BL_OUT=analysis "$PYTHON" analysis/precompute_figdata.py
    BL_DB="$DB" BL_OUT=analysis "$PYTHON" analysis/stats_baseline.py
    log "2/2  Regenerate figures from $DB and verify the paper values"
    local since; since=$(date -d '1 second ago' +%Y-%m-%dT%H:%M:%S)
    BL_DB="$DB" "$PYTHON" analysis/make_figs.py
    BL_DB="$DB" "$PYTHON" analysis/analyze_extra.py
    figs_written "$since"
    "$PYTHON" analysis/verify_values.py
}

# --------------------------------------------------------------------------
scan() {
    local SDIR="${SCANNERS_DIR:-scanners}"
    while [ $# -gt 0 ]; do
        case "$1" in
            --scanners-dir) SDIR="$2"; shift 2 ;;
            *) echo "unknown option for scan: $1" >&2; usage 2 ;;
        esac
    done

    [ -d "$SDIR" ] || {
        echo "scanner pipeline not found: $SDIR" >&2
        echo "Clone ChimangoScan/scanners and pass --scanners-dir PATH." >&2
        exit 1
    }
    [ -f "$SDIR/config/config.yaml" ] || {
        echo "prepared scanner config not found: $SDIR/config/config.yaml" >&2
        echo "Configure it as documented in README before running a scan." >&2
        exit 1
    }
    command -v docker >/dev/null || { echo "docker is required for scan mode" >&2; exit 1; }
    docker info >/dev/null 2>&1 || { echo "Docker daemon is not available" >&2; exit 1; }
    command -v uv >/dev/null || { echo "uv is required for scan mode" >&2; exit 1; }

    log "Execute the configured six-scanner pipeline"
    echo "Input of record: $HERE/data/random_sample.jsonl"
    echo "The prepared config must select syft, trivy, grype, osv, dockle, and trufflehog."
    (
        cd "$SDIR"
        uv run scanners seed
        uv run scanners run --workers 2 --scan-parallelism 1
        uv run scanners report
    )
    echo "Scan finished. Pass its reports SQLite explicitly to:"
    echo "  ./reproduce.sh analyze --db /path/to/bl_snap.db"
}

# --------------------------------------------------------------------------
case "${1:-}" in
    precomputed) shift; precomputed "$@" ;;
    analyze)     shift; analyze "$@" ;;
    scan)        shift; scan "$@" ;;
    verify)      shift; verify "$@" ;;
    dataset)     shift; dataset "$@" ;;
    -h|--help|help|"") usage 0 ;;
    *) echo "unknown mode: $1" >&2; usage 2 ;;
esac
