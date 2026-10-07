# Single entry point for humans, agents, and CI. CI calls the same targets.

SWIFT_FORMAT_PATHS := $(wildcard Sources Tests Package.swift)

.PHONY: setup format lint build test check

setup:
	git config core.hooksPath .githooks

format:
	swift format format --in-place --recursive --parallel $(SWIFT_FORMAT_PATHS)

lint:
	swift format lint --strict --recursive --parallel $(SWIFT_FORMAT_PATHS)

build:
	swift build --build-tests

test:
	swift test --parallel

check: lint build test
	@echo "make check: all checks passed"
