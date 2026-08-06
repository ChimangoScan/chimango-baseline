#!/usr/bin/env bash
# Prepare everything this artifact needs, in one command:
#
#     ./scripts/bootstrap.sh
#
# Picks a Python version the pinned dependencies actually ship wheels for,
# creates .venv, installs requirements.txt into it, and verifies the imports.
# When a system package is missing, it prints the exact command to run and stops
# instead of failing halfway through.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# numpy 1.26.4 and matplotlib 3.8.4, the versions used to produce the paper,
# publish wheels for CPython 3.9 to 3.12 only. A newer interpreter would try to
# build them from source and fail, so the search stops at 3.12.
SUPPORTED="3.12 3.11 3.10"

say() { printf '%s\n' "$*"; }

# 1. An interpreter whose version the pinned wheels cover.
PY=""
for v in $SUPPORTED; do
    if command -v "python$v" >/dev/null 2>&1; then PY="python$v"; break; fi
done

if [ -z "$PY" ]; then
    if command -v python3 >/dev/null 2>&1 &&
       python3 -c 'import sys; raise SystemExit(0 if (3,10) <= sys.version_info[:2] <= (3,12) else 1)'; then
        PY=python3
    else
        cur="$(python3 -V 2>&1 || echo 'not installed')"
        say "No usable Python found. Need one of: $SUPPORTED (found: $cur)."
        say ""
        say "numpy 1.26.4 and matplotlib 3.8.4, the versions used for the paper,"
        say "publish wheels only up to Python 3.12, so a newer interpreter cannot"
        say "install them. Install a supported one and re-run this script:"
        say ""
        say "    sudo apt install python3.12 python3.12-venv"
        exit 1
    fi
fi

# 2. That interpreter must be able to build a virtual environment. On Debian and
#    Ubuntu the venv module is packaged separately and is often absent.
if ! "$PY" -c 'import ensurepip' >/dev/null 2>&1; then
    say "$PY is installed but cannot create virtual environments (no ensurepip)."
    say "Install the matching venv package and re-run this script:"
    say ""
    say "    sudo apt install ${PY}-venv"
    exit 1
fi

say "==> Using $("$PY" -V 2>&1)"

# 3. Build the environment and install the pinned dependencies into it.
if [ ! -x .venv/bin/python ]; then
    say "==> Creating .venv"
    "$PY" -m venv .venv
fi
say "==> Installing pinned dependencies"
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements.txt

# 4. Prove the environment works before claiming success.
say "==> Verifying"
.venv/bin/python - <<'PY'
import sqlite3, sys
import matplotlib, numpy, zstandard
print(f"    python {sys.version.split()[0]}")
print(f"    matplotlib {matplotlib.__version__}, numpy {numpy.__version__}, "
      f"zstandard {zstandard.__version__}, sqlite3 {sqlite3.sqlite_version}")
PY

say ""
say "Ready. Next:"
say "    make test              # offline check, no dataset, under a second"
say "    ./reproduce.sh analyze # full reproduction, downloads the dataset"
