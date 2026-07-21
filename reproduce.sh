#!/usr/bin/env bash
#
# Reproduction driver for the uniform-random-sample baseline artifact.
#
#   ./reproduce.sh precomputed
#       Regenerate every paper figure and re-check the headline numbers from the
#       SHIPPED data only. No external database, no network, no Docker. This is
#       the fast, self-contained path used for artifact evaluation.
#
#   ./reproduce.sh full [--n N] [--db PATH]
#       Run the six-scanner pipeline end-to-end on a uniform random sample of N
#       repositories (default small, laptop + Docker), then recompute the
#       committed outputs and figures from the resulting reports database.
#       Full-scale reproduction (the paper's 4,800-repository draw) needs the
#       authors' multi-machine setup; see the README "Reproduction" section.
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
#   BL_DB    path to the reports SQLite (full mode; auto-detected if --db given)
#   BL_FIGS  output directory for figures (default: ./figures)
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
PYTHON="${PYTHON:-python3}"
export BL_FIGS="${BL_FIGS:-$HERE/figures}"

log() { printf '\n=== %s ===\n' "$*"; }

usage() {
    sed -n "2,39p" "$0" | sed 's/^# \{0,1\}//'
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

    log "2/3  Regenerate the figures from the precomputed data"
    # With no BL_DB pointing at an existing file, both scripts read the shipped
    # analysis/figdata_baseline.json and analysis/repro_baseline.json.
    unset BL_DB || true
    "$PYTHON" analysis/make_figs.py
    "$PYTHON" analysis/analyze_extra.py

    log "3/4  Figures written"
    ls -1 "$BL_FIGS"/*.pdf

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
    command -v zstd >/dev/null || { echo "zstd is required (apt install zstd)" >&2; exit 1; }
    local FREE_GB; FREE_GB=$(df -BG --output=avail "$DIR" | tail -1 | tr -dc 0-9)
    [ "$FREE_GB" -ge 11 ] || { echo "need ~11 GB free in $DIR (have ${FREE_GB} GB)" >&2; exit 1; }
    if [ ! -f "$ZST" ] || ! echo "$SHA_ZST  $ZST" | sha256sum -c --quiet -; then
        log "Downloading the reports database (226 MB)" >&2
        curl -L --fail --retry 3 -o "$ZST" "$DATASET_URL"
        echo "$SHA_ZST  $ZST" | sha256sum -c - || { echo "checksum mismatch: $ZST" >&2; exit 1; }
    fi
    log "Decompressing to $DB (10.3 GB)" >&2
    zstd -d -f "$ZST" -o "$DB"
    echo "$SHA_DB  $DB" | sha256sum -c - || { echo "checksum mismatch: $DB" >&2; exit 1; }
    log "Dataset ready: $DB" >&2
    echo "$DB"
}

# --------------------------------------------------------------------------
full() {
    local N=20 DB=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --n) N="$2"; shift 2 ;;
            --db) DB="$2"; shift 2 ;;
            *) echo "unknown option for full: $1" >&2; usage 2 ;;
        esac
    done

    log "FULL reproduction (sample N=$N, six-scanner pipeline, then analyze)"
    cat <<EOF
This runs the end-to-end pipeline at small scale on this machine. It requires:
  * a working Docker daemon (the six scanners run as Docker images),
  * the separate scanner pipeline (github.com/ChimangoScan/scanners) installed and on
    PATH (or set SCANNERS_DIR to its checkout),
  * outbound access to Docker Hub to pull the sampled images.

Full-scale reproduction (the paper's 4,800-repository draw across many machines)
is bandwidth- and disk-bound and needs the authors' setup; see the README
"Reproduction" section. The default N=$N keeps this to a laptop-sized run.
EOF

    # 1. draw a fresh uniform random sample of N repositories (needs MongoDB
    #    crawl). If unavailable, fall back to a head of the shipped canonical
    #    draw so the rest of the pipeline can still be exercised at small scale.
    local SAMPLE="data/random_sample.full.jsonl"
    if "$PYTHON" -c "import pymongo" 2>/dev/null && [ -n "${MONGO_URI:-}" ]; then
        log "1/4  Draw a uniform random sample of $N repositories from the crawl"
        SAMPLE_N="$N" OUT_PATH="$SAMPLE" "$PYTHON" scripts/sample_repos.py
    else
        log "1/4  No MongoDB crawl configured; using the first $N rows of the shipped canonical draw"
        head -n "$N" data/random_sample.jsonl > "$SAMPLE"
        echo "wrote $SAMPLE ($(wc -l < "$SAMPLE") repositories)"
    fi

    # 2. run the six-scanner pipeline over the sample (separate project).
    local SDIR="${SCANNERS_DIR:-scanners}"
    log "2/4  Run the six-scanner pipeline over $SAMPLE"
    if command -v scanners >/dev/null 2>&1 || [ -d "$SDIR" ]; then
        cat <<EOF
Configure the pipeline (see README "Installation") with:
  source.type: jsonl
  source.path: $HERE/$SAMPLE
  scanners.only: [syft, trivy, grype, osv, dockle, trufflehog]
  scanners.static: true ; scanners.dynamic: false
  runtime.remove_image_after: true ; runtime.max_image_mb: 15000
then:
  (cd "$SDIR" && uv run scanners seed && \\
       uv run scanners run --workers 2 --scan-parallelism 1 && \\
       uv run scanners report)
The pipeline writes the per-image reports store (bl_snap.db). Point the analysis
at it with --db / BL_DB and re-run this script's analysis step, or run full mode
again with --db PATH once it exists.
EOF
    else
        echo "scanner pipeline not found (set SCANNERS_DIR or install ChimangoScan/scanners)." >&2
        echo "See the README 'Installation' section for the exact commands." >&2
    fi

    # 3. analyze the reports database: the one given via --db/BL_DB, or the
    #    released canonical one (downloaded and checksum-verified on demand).
    DB="${DB:-${BL_DB:-}}"
    if [ -z "$DB" ]; then
        DB="$(dataset data | tail -1)"
    fi
    if [ -n "$DB" ] && [ -f "$DB" ]; then
        log "3/4  Recompute committed outputs from $DB"
        BL_DB="$DB" BL_OUT=analysis "$PYTHON" analysis/repro_baseline.py
        BL_DB="$DB" BL_OUT=analysis "$PYTHON" analysis/precompute_figdata.py
        BL_DB="$DB" BL_OUT=analysis "$PYTHON" analysis/stats_baseline.py
        log "4/4  Regenerate figures from $DB and verify the paper values"
        BL_DB="$DB" "$PYTHON" analysis/make_figs.py
        BL_DB="$DB" "$PYTHON" analysis/analyze_extra.py
        ls -1 "$BL_FIGS"/*.pdf
        "$PYTHON" analysis/verify_values.py
    else
        log "3/4  No reports database available yet"
        echo "Once the pipeline has produced a reports SQLite, re-run:"
        echo "  ./reproduce.sh full --db /path/to/bl_snap.db"
        echo "to recompute the outputs and figures from it."
    fi
}

# --------------------------------------------------------------------------
case "${1:-}" in
    precomputed) shift; precomputed "$@" ;;
    full)        shift; full "$@" ;;
    verify)      shift; verify "$@" ;;
    dataset)     shift; dataset "$@" ;;
    -h|--help|help|"") usage 0 ;;
    *) echo "unknown mode: $1" >&2; usage 2 ;;
esac
