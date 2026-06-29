// swift-tools-version:5.5
import PackageDescription

let package = Package(
    name: "Shield",
    platforms: [
        .macOS(.v11),
        .iOS(.v14),
        .tvOS(.v14),
        .watchOS(.v7)
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
