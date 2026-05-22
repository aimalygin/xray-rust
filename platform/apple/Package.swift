// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "XrayMobileAdapter",
    platforms: [
        .iOS(.v13),
        .tvOS(.v17),
        .macOS(.v11),
    ],
    products: [
        .library(name: "XrayMobileAdapter", targets: ["XrayMobileAdapter"]),
    ],
    targets: [
        .binaryTarget(
            name: "XrayRust",
            path: "../../target/mobile/apple/XrayRust.xcframework"
        ),
        .target(
            name: "XrayMobileAdapter",
            dependencies: ["XrayRust"]
        ),
    ]
)
