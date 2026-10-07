# ``PassportKitTesting``

A fake authorization server and test clocks, so flows run offline and without
sleeping.

## Overview

``FakeAuthorizationServer`` plugs into PassportKit as its
`HTTPTransport`. It implements the metadata, authorization,
token, device authorization and revocation endpoints and a bearer-protected
resource well enough to run every flow, and it is scriptable: rotation and
reuse leeway, narrowed scopes, refused resources, device approval, delays and
failures. See the "Testing" article of PassportKit for a walkthrough.

Add this library to test targets only.

## Topics

### The fake server

- ``FakeAuthorizationServer``
- ``RecordedRequest``

### Transports

- ``RecordingTransport``

### Clocks and randomness

- ``ManualClock``
- ``FixedWallClock``
- ``SequenceRandomSource``
