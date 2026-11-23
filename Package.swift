// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "GatePass",
  platforms: [.macOS(.v14), .iOS(.v17)],
  products: [
    .library(name: "GatePassProtocol", targets: ["GatePassProtocol"]),
    .executable(name: "GatePassServer", targets: ["GatePassServer"]),
    .executable(name: "GatePassAdmin", targets: ["GatePassAdmin"]),
  ],
  dependencies: [
    .package(url: "https://github.com/vapor/fluent.git", from: "4.12.0"),
    .package(url: "https://github.com/swiftlang/swift-testing.git", exact: "6.2.1"),
    .package(url: "https://github.com/vapor/vapor.git", from: "4.115.0"),
    .package(url: "https://github.com/vapor/fluent-postgres-driver.git", from: "2.10.0"),
    .package(url: "https://github.com/vapor/sql-kit.git", from: "3.32.0"),
    .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
    .package(url: "https://github.com/apple/swift-log.git", exact: "1.16.2"),
  ],
  targets: [
    .target(name: "GatePassProtocol"),
    .target(
      name: "GatePassService",
      dependencies: [
        "GatePassProtocol", .product(name: "Fluent", package: "fluent"),
        .product(name: "Vapor", package: "vapor"),
        .product(name: "FluentPostgresDriver", package: "fluent-postgres-driver"),
        .product(name: "SQLKit", package: "sql-kit"),
      ]),
    .executableTarget(
      name: "GatePassServer",
      dependencies: ["GatePassService", .product(name: "Vapor", package: "vapor")]),
    .executableTarget(
      name: "GatePassAdmin",
      dependencies: [
        "GatePassProtocol", .product(name: "ArgumentParser", package: "swift-argument-parser"),
      ]),
    .testTarget(
      name: "GatePassTests",
      dependencies: [
        "GatePassProtocol", "GatePassService", .product(name: "Testing", package: "swift-testing"),
      ]),
  ],
  swiftLanguageModes: [.v6]
)
