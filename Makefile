# SmartDelegate: the same targets as make.ps1 (Windows). Everything is done by
# scripts/sd.py; this file only names the targets. Details: docs/BUILD.md.
#
#   make bootstrap        fresh clone -> .venv, every port built, launchers in build/bin, quick verification
#   make doctor           which toolchains are here, what each enables, how to install the rest
#   make build            build every port whose toolchain is here; write the launchers
#   make test             the reference's unit tests (tests/)
#   make conformance      the two shared suites against every installed port (ports/conformance/run.sh)
#   make matrix           every port against every other (ports/conformance/matrix.py)
#   make harness          the example company's policy tests and the scenario harness (harness/README.md)
#   make live             suites against real services: live/idp/run.sh (Keycloak), then live/run.sh all
#                         (upstream, boundary as root, load). ARGS=--quick for the short form; ARGS="idp upstream" for parts
#   make load             load and soak, gated: python -m live.load --check live/load/thresholds.json (report in build/reports/load)
#   make all              bootstrap --full: all of the above plus test_all.sh
#   make dist             release artifacts and SHA256SUMS in dist/
#   make clean            remove .venv, build/, dist/, caches (ARGS=--deep: also ports/rust/target)
#   make docker-build     build docker/Dockerfile.dev and docker/Dockerfile.daemon   (not tested: see docs/BUILD.md)
#   make docker-test      the live topology of docker/docker-compose.yml             (not tested: see docs/BUILD.md)
#
# Extra options go in ARGS:   make conformance ARGS="--only go,php"   make bootstrap ARGS=--offline
#
# `make build` used to be `python -m build`; that is part of `make dist` now.

PYTHON ?= $(shell command -v python3 2>/dev/null || command -v python 2>/dev/null)
SD = $(PYTHON) scripts/sd.py
ARGS ?=

.PHONY: help bootstrap doctor build test conformance matrix harness live load all dist clean docker-build docker-test demo all-tests

help:
	@sed -n '4,23p' Makefile | sed 's/^# \{0,1\}//'

bootstrap:
	./bootstrap.sh $(ARGS)

all:
	./bootstrap.sh --full $(ARGS)

doctor:
	@$(PYTHON) scripts/doctor.py $(ARGS)

build test conformance matrix harness live load dist clean docker-build docker-test:
	$(SD) $@ $(ARGS)

# kept from before
demo:
	@if [ -x build/bin/smartdelegate ]; then build/bin/smartdelegate --demo; else PYTHONPATH=src $(PYTHON) -m sf_smartdelegate --demo; fi

all-tests:
	./test_all.sh
