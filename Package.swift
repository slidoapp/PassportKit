// swift-tools-version: 6.2

import PackageDescription

let swiftSettings: [SwiftSetting] = [
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .treatAllWarnings(as: .error),
]

let package = Package(
    name: "PassportKit",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
        .tvOS(.v17),
        .watchOS(.v10),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "PassportKit", targets: ["PassportKit"]),
        .library(name: "PassportKitApple", targets: ["PassportKitApple"]),
        .library(name: "PassportKitTesting", targets: ["PassportKitTesting"]),
    ],
    targets: [
        .target(name: "PassportKit", swiftSettings: swiftSettings),
        .target(name: "PassportKitApple", dependencies: ["PassportKit"], swiftSettings: swiftSettings),
        .target(name: "PassportKitTesting", dependencies: ["PassportKit"], swiftSettings: swiftSettings),
        .testTarget(
            name: "PassportKitTests", dependencies: ["PassportKit", "PassportKitTesting"], swiftSettings: swiftSettings),
        .testTarget(
            name: "PassportKitTestingTests",
            dependencies: ["PassportKit", "PassportKitTesting"],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "ConformanceTests", dependencies: ["PassportKit", "PassportKitTesting"], swiftSettings: swiftSettings),
        .testTarget(
            name: "IntegrationTests",
            dependencies: ["PassportKit", "PassportKitApple"],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "PassportKitAppleTests",
            dependencies: ["PassportKitApple", "PassportKitTesting"],
            swiftSettings: swiftSettings
        ),
        .executableTarget(
            name: "passportkit-example",
            dependencies: ["PassportKit", "PassportKitApple"],
            swiftSettings: swiftSettings
        ),
    ]
)
