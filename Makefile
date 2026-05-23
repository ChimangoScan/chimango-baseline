# Reproduction entry points for the uniform-random-sample baseline artifact.
#
#   make install      install the Python dependencies (matplotlib, numpy, ...)
#   make precomputed   regenerate every figure + re-check headline numbers from
#                      the shipped data only (no database, no network)
#   make full          run the six-scanner pipeline at small scale, then analyze
#                      (needs Docker + the separate scanner pipeline; see README)
#   make test          the minimal, self-contained check (no third-party deps)
#   make clean         remove generated figures
#
# Variables:
#   PYTHON   python interpreter (default: python3)
#   N        sample size for `make full` (default: 20)
#   BL_DB    path to the reports SQLite for `make full` (optional)

PYTHON ?= python3
N      ?= 20

.PHONY: all install precomputed full test clean

all: precomputed

install:
	$(PYTHON) -m pip install -r requirements.txt

precomputed:
	./reproduce.sh precomputed

full:
	./reproduce.sh full --n $(N) $(if $(BL_DB),--db $(BL_DB),)

test:
	$(PYTHON) scripts/minimal_test.py

clean:
	rm -f figures/*.pdf
