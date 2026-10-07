#!/bin/sh
# Fails when the core module reaches for the system clock, randomness, sleeping or the shared URLSession
# outside the default implementations of the injected seams (docs/spec.md §15, ADR 0006).
set -eu

cd "$(dirname "$0")/.."

# Files that may use the system APIs, each justified:
#   SystemWallClock.swift      default WallClock
#   SystemRandomSource.swift   default RandomSource
#   URLSessionTransport*.swift default HTTPTransport; owns its URLSession

patterns='Date\(\)|Date\.now|Task\.sleep|URLSession\.shared|UUID\(\)|\.random\(|arc4random|SystemRandomNumberGenerator'

# Comment lines are ignored: documentation may name the forbidden APIs.
violations=$(grep -rnE "$patterns" Sources/PassportKit --include='*.swift' \
    --exclude=SystemWallClock.swift --exclude=SystemRandomSource.swift --exclude='URLSessionTransport*.swift' \
    | grep -Ev '^[^:]+:[0-9]+:[[:space:]]*//' || true)

if [ -n "$violations" ]; then
    echo "check-determinism: forbidden API outside the default seam implementations:" >&2
    echo "$violations" >&2
    echo "Inject WallClock, RandomSource, Clock or HTTPTransport instead (docs/spec.md §15)." >&2
    exit 1
fi
echo "check-determinism: ok"
