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
            path: "Sources/Shield"
        ),
        .testTarget(
            name: "ShieldTests",
            dependencies: ["Shield"],
            path: "Tests/ShieldTests"
        ),
    ]
)
