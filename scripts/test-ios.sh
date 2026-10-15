#!/bin/sh
# Runs the test suite on the newest available iPhone simulator. Needs Xcode with an iOS runtime.
set -eu

device=$(xcrun simctl list devices available --json | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
runtimes = sorted((r for r in devices if ".iOS-" in r), key=lambda r: [int(p) for p in r.rsplit(".iOS-", 1)[1].split("-")])
for runtime in reversed(runtimes):
    for device in devices[runtime]:
        if device["name"].startswith("iPhone"):
            print(device["udid"])
            sys.exit(0)
sys.exit("No available iPhone simulator.")
')

# Boot while building: building needs no booted simulator, and a cold boot takes minutes on CI. The tests
# start only once the boot finished, so they do not compete with it.
xcrun simctl bootstatus "$device" -b >/dev/null &
boot=$!

xcodebuild build-for-testing \
    -scheme PassportKit-Package \
    -destination "id=$device" \
    -derivedDataPath .build/ios

wait "$boot"

results=.build/ios/TestResults.xcresult
rm -rf "$results"
xcodebuild test-without-building \
    -scheme PassportKit-Package \
    -destination "id=$device" \
    -derivedDataPath .build/ios \
    -resultBundlePath "$results"
