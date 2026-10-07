import Foundation

/// The result of starting the device authorization grant (RFC 8628 §3.2): what to show the user, and what the
/// client needs to poll.
///
/// The device code is internal and never printed. The lifetime is tracked on the client's injected clock
/// (ADR 0006), so ``remainingLifetime`` keeps counting down after this value is created.
public struct DeviceAuthorization: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The code the user types at ``verificationURI`` (`user_code`).
    public internal(set) var userCode: String
    /// Where the user enters ``userCode`` (`verification_uri`; the `verification_url` alias is also accepted).
    public internal(set) var verificationURI: URL
    /// A verification URI that already contains the user code, for QR codes. Used verbatim.
    public internal(set) var verificationURIComplete: URL?
    /// The lifetime granted by the server (`expires_in`).
    public internal(set) var expiresIn: Duration
    /// The wall-clock time the authorization expires, for display. Polling uses the injected clock, not this value.
    public internal(set) var expiresAt: Date
    /// The minimum polling interval (`interval`); 5 seconds when the server omits it (RFC 8628 §3.2).
    public internal(set) var interval: Duration

    let deviceCode: Secret
    private let stopwatch: Stopwatch

    /// Creates a value, for example to show the device flow screen in a preview or a UI test. A real value comes
    /// from ``OAuthClient/startDeviceAuthorization(scope:resources:additionalParameters:)``.
    ///
    /// `clock` measures ``remainingLifetime``.
    public init(
        deviceCode: Secret,
        userCode: String,
        verificationURI: URL,
        verificationURIComplete: URL? = nil,
        expiresIn: Duration,
        expiresAt: Date,
        interval: Duration = .seconds(5),
        clock: any Clock<Duration> = ContinuousClock()
    ) {
        self.init(
            deviceCode: deviceCode, userCode: userCode, verificationURI: verificationURI,
            verificationURIComplete: verificationURIComplete, expiresIn: expiresIn, expiresAt: expiresAt,
            interval: interval, stopwatch: Stopwatch(clock: clock))
    }

    init(
        deviceCode: Secret,
        userCode: String,
        verificationURI: URL,
        verificationURIComplete: URL?,
        expiresIn: Duration,
        expiresAt: Date,
        interval: Duration,
        stopwatch: Stopwatch
    ) {
        self.deviceCode = deviceCode
        self.userCode = userCode
        self.verificationURI = verificationURI
        self.verificationURIComplete = verificationURIComplete
        self.expiresIn = expiresIn
        self.expiresAt = expiresAt
        self.interval = interval
        self.stopwatch = stopwatch
    }

    /// How long the authorization remains valid, measured on the injected clock; zero once expired.
    public var remainingLifetime: Duration { max(.zero, expiresIn - stopwatch.elapsed) }

    /// A summary without the device code.
    public var description: String {
        "DeviceAuthorization(userCode: \(userCode), verificationURI: \(HTTPRequest.redactedTarget(of: verificationURI)), expiresIn: \(expiresIn), interval: \(interval))"
    }

    /// A summary without the device code.
    public var debugDescription: String { description }

    /// A mirror exposing the summary only, so the device code never shows up in dumps.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

extension DeviceAuthorization {
    /// The interval used when the server omits `interval` (RFC 8628 §3.2).
    static let defaultInterval = Duration.seconds(5)
    /// The longest polling interval accepted from the server or reached through `slow_down`. A larger value is
    /// not a usable polling schedule, and converting it unchecked would trap.
    static let maximumInterval = Duration.seconds(3600)

    /// Parses the body of a 2xx device authorization response (RFC 8628 §3.2).
    ///
    /// `device_code`, `user_code`, a verification URI and `expires_in` are required. A missing, non-positive
    /// or unparsable `interval` means 5 seconds, an `interval` above one hour is rejected; a `verification_uri_complete` that is unparsable or not `https` is dropped. A verification URI must be `https`
    /// (or `http` on a loopback host), else the response is invalid.
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidResponse``.
    init(parsing data: Data, wallClock: any WallClock, clock: any Clock<Duration>) throws {
        guard case .object(let members)? = try? JSONDecoder().decode(JSONValue.self, from: data) else {
            throw PassportError(.invalidResponse, detail: "The device authorization response is not JSON.")
        }
        func text(_ names: String...) -> String? {
            for name in names {
                if case .string(let value)? = members[name], !value.isEmpty { return value }
            }
            return nil
        }
        func seconds(_ name: String) -> Double? {
            switch members[name] {
            case .number(let value)?: value
            case .string(let value)?: Double(value.trimmingCharacters(in: .whitespaces))
            default: nil
            }
        }
        // The URIs are shown to a person, who is told to type a code there: only https (or http on loopback).
        func url(_ value: String?) -> URL? {
            guard let value, let url = URL(string: value),
                (try? Endpoints.validateSecureTransport(of: url, name: "")) != nil
            else { return nil }
            return url
        }
        guard let deviceCode = text("device_code"), let userCode = text("user_code"),
            // `verification_url` is an interoperability alias: some providers shipped it before RFC 8628 settled on `_uri`.
            let verificationURI = url(text("verification_uri", "verification_url")),
            let lifetime = seconds("expires_in"), lifetime.isFinite, lifetime > 0
        else {
            throw PassportError(
                .invalidResponse,
                detail: "The device authorization response lacks a required member."
            )
        }
        let pollInterval = seconds("interval").flatMap { $0.isFinite && $0 > 0 ? $0 : nil }
        if let pollInterval, pollInterval > Double(Self.maximumInterval.components.seconds) {
            throw PassportError(
                .invalidResponse,
                detail: "The device authorization response has an unusable polling interval."
            )
        }
        let expiresIn = Duration.seconds(min(lifetime, 3_153_600_000))
        self.init(
            deviceCode: Secret(deviceCode),
            userCode: userCode,
            verificationURI: verificationURI,
            verificationURIComplete: url(text("verification_uri_complete")),
            expiresIn: expiresIn,
            expiresAt: wallClock.now().addingTimeInterval(Double(expiresIn.components.seconds)),
            interval: pollInterval.map { Duration.seconds($0) } ?? Self.defaultInterval,
            stopwatch: Stopwatch(clock: clock)
        )
    }
}
