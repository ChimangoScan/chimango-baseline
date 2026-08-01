# Reproduction entry points for the uniform-random-sample baseline artifact.
#
#   make install      install the Python dependencies (matplotlib, numpy, ...)
#   make precomputed   regenerate every figure + re-check headline numbers from
#                      the shipped data only (no database, no network)
#   make analyze       recompute outputs from the released or supplied reports DB
#   make scan          execute the separately configured scanner pipeline
#   make verify        compare every paper number exactly against the committed
#                      outputs (expected/paper_values.json)
#   make test          the minimal, self-contained check (no third-party deps)
#   make clean         remove generated figures
#
# Variables:
#   PYTHON   python interpreter (default: python3)
#   BL_DB    path to the reports SQLite for `make analyze` (optional)
#   SCANNERS_DIR path to a configured ChimangoScan/scanners checkout

PYTHON ?= python3
.PHONY: all install precomputed analyze scan verify test clean

all: precomputed

install:
	$(PYTHON) -m pip install -r requirements.txt

precomputed:
	./reproduce.sh precomputed

analyze:
	./reproduce.sh analyze $(if $(BL_DB),--db $(BL_DB),)

scan:
	./reproduce.sh scan $(if $(SCANNERS_DIR),--scanners-dir $(SCANNERS_DIR),)

verify:
	./reproduce.sh verify

test:
	$(PYTHON) scripts/minimal_test.py

clean:
	rm -f figures/*.pdf
