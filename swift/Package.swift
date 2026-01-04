// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "Shield",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        .library(
            name: "Shield",
            targets: ["Shield"]),
    ],
    targets: [
        .target(
            name: "Shield",
            dependencies: []),
        .testTarget(
            name: "ShieldTests",
            dependencies: ["Shield"]),
    ]
)
