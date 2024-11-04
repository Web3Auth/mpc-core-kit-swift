// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "mpc-core-kit-swift",
    platforms: [ .iOS(.v14), .macOS(.v11) ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "mpc-core-kit-swift",
            targets: ["mpc-core-kit-swift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/jwt-kit.git", from: "4.0.0"),
        .package(url: "https://github.com/torusresearch/tss-client-swift.git", from: "5.0.0"),
        .package(url: "https://github.com/tkey/tkey-mpc-swift", branch : "encapsulate_torusnetwork" ), // 4.0.0
        .package(url: "https://github.com/torusresearch/customauth-swift-sdk", from: "11.0.1"),
        .package(url: "https://github.com/auth0/JWTDecode.swift", from: "3.2.0")
    ],
    
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "mpc-core-kit-swift",
            dependencies: [
                .product(name: "CustomAuth", package: "customauth-swift-sdk"),
                .product(name: "tkey", package: "tkey-mpc-swift" ),
                .product(name: "tssClientSwift", package: "tss-client-swift" ),
                .product(name: "JWTDecode", package: "JWTDecode.swift")
            ]
        ),
        .testTarget(
            name: "mpc-kit-swiftTests",
            dependencies: ["mpc-core-kit-swift", .product(name: "JWTKit", package: "jwt-kit")]),
    ]
)
