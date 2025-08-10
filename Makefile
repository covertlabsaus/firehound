.PHONY: pipeline help

# Defaults (override with: make pipeline BASE=$(pwd) IDS=ids.txt WORKERS=8 IPATOOL_PAR=3)
BASE ?= $(shell pwd)
IDS ?=
WORKERS ?= 8
IPATOOL_PAR ?= 3
VERBOSE ?= 1
FULL_COUNTS ?=

help:
    @echo "Targets:"
    @echo "  pipeline  - Run the end-to-end pipeline (fetch.py -> audit.py -> summarize.py)"
	@echo "Vars: BASE, IDS, WORKERS, IPATOOL_PAR, VERBOSE, FULL_COUNTS, IPATOOL_PASSPHRASE"
    @echo "Example: make pipeline BASE=\"$$(pwd)\" IDS=ids.txt WORKERS=8 IPATOOL_PAR=3"

pipeline:
	IPATOOL_PASSPHRASE="$${IPATOOL_PASSPHRASE}" \
	WORKERS=$(WORKERS) \
	IPATOOL_PAR=$(IPATOOL_PAR) \
	VERBOSE=$(VERBOSE) \
	FULL_COUNTS=$(FULL_COUNTS) \
	./pipeline.sh --base $(BASE) $(if $(IDS),--ids $(IDS))


