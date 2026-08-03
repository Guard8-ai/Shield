// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "Shield",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
        .tvOS(.v14),
        .watchOS(.v7)
    ],
    products: [
        .library(
            name: "Shield",
            targets: ["Shield"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "Shield",
            dependencies: [],
            path: "Sources/Shield",
            // PqHybrid.swift targets CryptoKit's MLKEM768, which exists only in
            // the macOS 26 / iOS 26 SDK and against an API still in flux. Excluded
            // from the build so the base AES-GCM module compiles on current Xcode;
            // re-include and finish it on Xcode 26+. See PqHybrid.swift header.
            exclude: ["PqHybrid.swift"]
        ),
        .testTarget(
            name: "ShieldTests",
            dependencies: ["Shield"],
            path: "Tests/ShieldTests",
            exclude: ["PqHybridTests.swift"]
        ),
    ]
)
