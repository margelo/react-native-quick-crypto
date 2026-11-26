// swift-tools-version: 6.4

import PackageDescription

let generated = "nitrogen/generated"
let package = Package(
  name: "QuickCryptoNitro",
  platforms: [.iOS(.v16), .macOS(.v13)],
  products: [.library(name: "QuickCryptoNitro", targets: ["QuickCryptoNitro"])],
  dependencies: [.package(path: "../nitro-core")],
  targets: [
    .binaryTarget(
      name: "QuickCryptoOpenSSL",
      url: "https://github.com/margelo/react-native-quick-crypto/releases/download/openssl-apple-3.6.2/QuickCryptoOpenSSL-3.6.2.zip",
      checksum: "a50e3c8473b0526b159ad8d105e97a90d1153a4a230388cc731ee23a7d0ad3a4"
    ),
    .target(
      name: "QuickCryptoNitro",
      dependencies: [.product(name: "NitroModules", package: "nitro-core"), "QuickCryptoOpenSSL"],
      path: ".",
      exclude: ["\(generated)/apple/c++/include/module.modulemap"],
      sources: [
        "backend", "cpp", "\(generated)/shared/c++", "\(generated)/apple/c++",
        "\(generated)/apple/QuickCryptoNitroAutolinking.cpp",
      ],
      publicHeadersPath: "\(generated)/apple/c++/include",
      cxxSettings: [
        .headerSearchPath("backend"),
        .headerSearchPath("cpp/include"),
        .headerSearchPath("\(generated)/shared/c++/include"),
        .headerSearchPath("ios/openssl/include"),
        .headerSearchPath("ios/openssl"),
        .unsafeFlags(["-include", "quickcrypto_openssl_prefix.h"]),
      ]
    ),
  ],
  cxxLanguageStandard: .cxx20
)
