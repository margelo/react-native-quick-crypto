///
/// QuickCrypto-Swift-Cxx-Umbrella.hpp
/// This file was generated by nitrogen. DO NOT MODIFY THIS FILE.
/// https://github.com/mrousavy/nitro
/// Copyright © 2024 Marc Rousavy @ Margelo
///

#pragma once

// Forward declarations of C++ defined types
// Forward declaration of `ArrayBuffer` to properly resolve imports.
namespace NitroModules { class ArrayBuffer; }
// Forward declaration of `AsymmetricKeyType` to properly resolve imports.
namespace margelo::nitro::crypto { enum class AsymmetricKeyType; }
// Forward declaration of `HybridKeyObjectHandleSpec` to properly resolve imports.
namespace margelo::nitro::crypto { class HybridKeyObjectHandleSpec; }
// Forward declaration of `HybridPbkdf2Spec` to properly resolve imports.
namespace margelo::nitro::crypto { class HybridPbkdf2Spec; }
// Forward declaration of `HybridRandomSpec` to properly resolve imports.
namespace margelo::nitro::crypto { class HybridRandomSpec; }
// Forward declaration of `JWK` to properly resolve imports.
namespace margelo::nitro::crypto { struct JWK; }
// Forward declaration of `JWKkty` to properly resolve imports.
namespace margelo::nitro::crypto { enum class JWKkty; }
// Forward declaration of `JWKuse` to properly resolve imports.
namespace margelo::nitro::crypto { enum class JWKuse; }
// Forward declaration of `KFormatType` to properly resolve imports.
namespace margelo::nitro::crypto { enum class KFormatType; }
// Forward declaration of `KeyDetail` to properly resolve imports.
namespace margelo::nitro::crypto { struct KeyDetail; }
// Forward declaration of `KeyEncoding` to properly resolve imports.
namespace margelo::nitro::crypto { enum class KeyEncoding; }
// Forward declaration of `KeyType` to properly resolve imports.
namespace margelo::nitro::crypto { enum class KeyType; }
// Forward declaration of `KeyUsage` to properly resolve imports.
namespace margelo::nitro::crypto { enum class KeyUsage; }
// Forward declaration of `NamedCurve` to properly resolve imports.
namespace margelo::nitro::crypto { enum class NamedCurve; }

// Include C++ defined types
#include "AsymmetricKeyType.hpp"
#include "HybridKeyObjectHandleSpec.hpp"
#include "HybridPbkdf2Spec.hpp"
#include "HybridRandomSpec.hpp"
#include "JWK.hpp"
#include "JWKkty.hpp"
#include "JWKuse.hpp"
#include "KFormatType.hpp"
#include "KeyDetail.hpp"
#include "KeyEncoding.hpp"
#include "KeyType.hpp"
#include "KeyUsage.hpp"
#include "NamedCurve.hpp"
#include <NitroModules/ArrayBuffer.hpp>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// C++ helpers for Swift
#include "QuickCrypto-Swift-Cxx-Bridge.hpp"

// Common C++ types used in Swift
#include <NitroModules/ArrayBufferHolder.hpp>
#include <NitroModules/AnyMapHolder.hpp>
#include <NitroModules/HybridContext.hpp>
#include <NitroModules/PromiseHolder.hpp>

// Forward declarations of Swift defined types
// Forward declaration of `HybridKeyObjectHandleSpecCxx` to properly resolve imports.
namespace QuickCrypto { class HybridKeyObjectHandleSpecCxx; }
// Forward declaration of `HybridPbkdf2SpecCxx` to properly resolve imports.
namespace QuickCrypto { class HybridPbkdf2SpecCxx; }
// Forward declaration of `HybridRandomSpecCxx` to properly resolve imports.
namespace QuickCrypto { class HybridRandomSpecCxx; }

// Include Swift defined types
#if __has_include("QuickCrypto-Swift.h")
// This header is generated by Xcode/Swift on every app build.
// If it cannot be found, make sure the Swift module's name (= podspec name) is actually "QuickCrypto".
#include "QuickCrypto-Swift.h"
#else
#error QuickCrypto's autogenerated Swift header cannot be found! Make sure the Swift module's name (= podspec name) is actually "QuickCrypto", and try building the app first.
#endif
