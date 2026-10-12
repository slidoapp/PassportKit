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
        .library(name: "PassportKitTesting", targets: ["PassportKitTesting"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-http-types.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.6.0"),
        .package(url: "https://github.com/slidoapp/SwiftKeychain.git", .upToNextMinor(from: "2.1.0")),
    ],
    targets: [
        .target(
            name: "PassportKit",
            dependencies: [
                .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "HTTPTypesFoundation", package: "swift-http-types"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "SwiftKeychain", package: "SwiftKeychain"),
            ],
            swiftSettings: swiftSettings
        ),
        .target(
            name: "PassportKitTesting",
            dependencies: [
                "PassportKit",
                .product(name: "HTTPTypes", package: "swift-http-types"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "PassportKitTests",
            dependencies: [
                "PassportKit", "PassportKitTesting", .product(name: "HTTPTypes", package: "swift-http-types"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "PassportKitTestingTests",
            dependencies: [
                "PassportKit", "PassportKitTesting", .product(name: "HTTPTypes", package: "swift-http-types"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "ConformanceTests",
            dependencies: [
                "PassportKit", "PassportKitTesting", .product(name: "HTTPTypes", package: "swift-http-types"),
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "IntegrationTests",
            dependencies: ["PassportKit"],
            swiftSettings: swiftSettings
        ),
        .executableTarget(
            name: "passportkit-example",
            dependencies: ["PassportKit"],
            swiftSettings: swiftSettings
        ),
    ]
)
