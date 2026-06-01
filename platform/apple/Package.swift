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
        .library(name: "XrayAppleShared", targets: ["XrayAppleShared"]),
        .library(name: "XrayAppleClient", targets: ["XrayAppleClient"]),
        .library(name: "XrayAppleTunnel", targets: ["XrayAppleTunnel"]),
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
        .target(
            name: "XrayAppleShared"
        ),
        .target(
            name: "XrayAppleClient",
            dependencies: [
                "XrayAppleShared",
                "XrayMobileAdapter",
            ]
        ),
        .target(
            name: "XrayAppleTunnel",
            dependencies: [
                "XrayAppleShared",
                "XrayMobileAdapter",
            ]
        ),
        .testTarget(
            name: "XrayAppleSharedTests",
            dependencies: ["XrayAppleShared"]
        ),
        .testTarget(
            name: "XrayAppleClientTests",
            dependencies: [
                "XrayAppleClient",
                "XrayAppleShared",
            ]
        ),
        .testTarget(
            name: "XrayAppleTunnelTests",
            dependencies: ["XrayAppleTunnel"]
        ),
        .testTarget(
            name: "XrayMobileAdapterTests",
            dependencies: ["XrayMobileAdapter"]
        ),
    ]
)
