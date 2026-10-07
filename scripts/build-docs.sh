#!/bin/sh
# Builds the DocC archive of every library and fails on any warning, which includes unresolved symbol
# links and malformed catalog content. Output goes to .build/docbuild.
set -eu

cd "$(dirname "$0")/.."

derived=.build/docbuild
log=$(mktemp)
trap 'rm -f "$log"' EXIT

for scheme in PassportKit PassportKitApple PassportKitTesting; do
    echo "docs: building $scheme"
    if ! xcodebuild docbuild -scheme "$scheme" -destination 'generic/platform=macOS' \
        -derivedDataPath "$derived" >"$log" 2>&1; then
        cat "$log" >&2
        echo "docs: $scheme failed to build" >&2
        exit 1
    fi
    warnings=$(grep -E ' warning: ' "$log" | sed -E 's/ \(in target .*//' | sort -u || true)
    if [ -n "$warnings" ]; then
        echo "$warnings" >&2
        echo "docs: $scheme has documentation warnings" >&2
        exit 1
    fi
done
echo "docs: ok ($derived/Build/Products/Debug/*.doccarchive)"
