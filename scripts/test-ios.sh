#!/bin/sh
# Runs the test suite on the newest available iPhone simulator. Needs Xcode with an iOS runtime.
set -eu

device=$(xcrun simctl list devices available --json | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
# A runtime key is ...SimRuntime.iOS-27-2; keys of device-specific runtimes add a suffix such as -iPhone19-4.
runtimes = [r for r in devices if ".iOS-" in r and all(p.isdigit() for p in r.rsplit(".iOS-", 1)[1].split("-"))]
runtimes.sort(key=lambda r: [int(p) for p in r.rsplit(".iOS-", 1)[1].split("-")])
for runtime in reversed(runtimes):
    for device in devices[runtime]:
        if device["name"].startswith("iPhone"):
            print(device["udid"])
            sys.exit(0)
sys.exit("No available iPhone simulator.")
')

# Boot first, so the tests do not compete with a cold simulator start.
xcrun simctl bootstatus "$device" -b >/dev/null

results=.build/ios/TestResults.xcresult
rm -rf "$results"
xcodebuild test \
    -scheme PassportKit-Package \
    -destination "id=$device" \
    -derivedDataPath .build/ios \
    -resultBundlePath "$results"
