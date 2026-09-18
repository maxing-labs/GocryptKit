// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "VaultCore",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(name: "VaultCore", targets: ["VaultCore"]),
        .executable(name: "vaultctl", targets: ["vaultctl"])
    ],
    dependencies: [],
    targets: [
        .binaryTarget(
            name: "libgocryptfs",
            path: "../../Engine/build/libgocryptfs.xcframework"
        ),
        .target(
            name: "VaultCore",
            dependencies: [
                "libgocryptfs"
            ],
            linkerSettings: [
                .linkedLibrary("resolv")
            ]
        ),
        .executableTarget(
            name: "vaultctl",
            dependencies: [
                "VaultCore"
            ]
        ),
        .testTarget(
            name: "VaultCoreTests",
            dependencies: [
                "VaultCore"
            ]
        )
    ]
)
