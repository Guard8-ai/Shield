// swift-tools-version:5.7
import PackageDescription

let package = Package(
    name: "Shield",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
        .tvOS(.v13),
        .watchOS(.v6)
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
            path: "Sources/Shield"
        ),
        .testTarget(
            name: "ShieldTests",
            dependencies: ["Shield"],
            path: "Tests/ShieldTests"
        ),
    ]
)
