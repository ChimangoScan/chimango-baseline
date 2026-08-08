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

# uv installs itself into ~/.local/bin (or ~/.cargo/bin) and only edits the shell
# rc files, so it is NOT on PATH in the shell that just installed it. Look in
# those directories too, otherwise a reviewer who follows our own instructions
# re-runs this script and is told again that uv is missing.
find_uv() {
    if command -v uv >/dev/null 2>&1; then command -v uv; return 0; fi
    for c in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
        [ -x "$c" ] && { printf '%s\n' "$c"; return 0; }
    done
    return 1
}

# Package-manager hints differ per distribution; print the one that applies
# instead of assuming Debian.
pkg_hint() {  # $1 = debian pkgs, $2 = fedora, $3 = arch, $4 = suse
    if   command -v apt-get >/dev/null 2>&1; then say "    sudo apt install $1"
    elif command -v dnf     >/dev/null 2>&1; then say "    sudo dnf install $2"
    elif command -v pacman  >/dev/null 2>&1; then say "    sudo pacman -S $3"
    elif command -v zypper  >/dev/null 2>&1; then say "    sudo zypper install $4"
    else
        say "    (your package manager) $1"
    fi
}

# 1. An interpreter whose version the pinned wheels cover.
PY=""
for v in $SUPPORTED; do
    if command -v "python$v" >/dev/null 2>&1; then PY="python$v"; break; fi
done

if [ -z "$PY" ] && command -v python3 >/dev/null 2>&1 &&
   python3 -c 'import sys; raise SystemExit(0 if (3,10) <= sys.version_info[:2] <= (3,12) else 1)' 2>/dev/null; then
    PY=python3
fi

# uv can fetch a matching interpreter without root and without a distribution
# package, which is the only option left when the system Python is too new. It
# is installed here rather than only suggested, so this script needs one run and
# not two, and it lands in the repository so nothing outside it is touched.
if [ -z "$PY" ]; then
    UV="$(find_uv || true)"
    if [ -z "$UV" ]; then
        say "==> System Python is out of range and uv is not installed."
        say "==> Fetching uv into $REPO/.uv (nothing outside this directory changes)"
        if ! curl -LsSf https://astral.sh/uv/install.sh \
             | env UV_INSTALL_DIR="$REPO/.uv" UV_NO_MODIFY_PATH=1 sh >/dev/null 2>&1; then
            cur="$(python3 -V 2>&1 || echo 'not installed')"
            say ""
            say "Could not download uv (no network?). Need a Python in: $SUPPORTED"
            say "(found: $cur). numpy 1.26.4 and matplotlib 3.8.4 publish wheels only"
            say "up to 3.12, so a newer interpreter cannot install them. Either:"
            say ""
            say "  install uv by hand, then re-run this script:"
            say "    curl -LsSf https://astral.sh/uv/install.sh | sh"
            say ""
            say "  or install a supported Python from your distribution:"
            pkg_hint "python3.12 python3.12-venv" "python3.12" "python312" "python312"
            exit 1
        fi
        UV="$REPO/.uv/uv"
    fi
    say "==> System Python is out of range; fetching 3.12 with uv"
    "$UV" python install 3.12
    PY="$("$UV" python find 3.12)"
fi

# 2. That interpreter must be able to build a virtual environment. On Debian and
#    Ubuntu the venv module is packaged separately and is often absent.
if ! "$PY" -c 'import ensurepip' >/dev/null 2>&1; then
    say "$PY is installed but cannot create virtual environments (no ensurepip)."
    say "Install the matching venv package and re-run this script:"
    say ""
    pkg_hint "${PY}-venv" "${PY}" "python" "${PY}"
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

# 5. The figures are typeset in the paper's serif face. Without it matplotlib
#    falls back to DejaVu Serif, whose wider glyphs crowd the labels. This does
#    not affect any number, so it is a warning and not a failure.
#    Ask matplotlib, which is what actually resolves the font when the figures are
#    drawn, instead of `fc-list`: fontconfig is not installed everywhere, and where
#    it is missing the check would be skipped in silence and the evaluator would only
#    find out at the end of a long run. This also keeps the warning here and the one
#    in analysis/figstyle.py from ever disagreeing.
if [ "$(.venv/bin/python - <<'PY'
from matplotlib import font_manager
want = ("Liberation Serif", "Nimbus Roman", "Times New Roman")
have = {f.name for f in font_manager.fontManager.ttflist}
print("ok" if any(n in have for n in want) else "missing")
PY
)" = "missing" ]; then
    say ""
    say "NOTE: the paper's serif font is not installed, so the regenerated figures"
    say "will differ typographically from the published ones (numbers unaffected)."
    say "To match them exactly:"
    pkg_hint "fonts-liberation" "liberation-serif-fonts" "ttf-liberation" "liberation-fonts"
fi

say ""
say "Ready. Next:"
say "    ./reproduce.sh test    # offline check, no dataset, under a second"
say "    ./reproduce.sh analyze # full reproduction, downloads the dataset"
