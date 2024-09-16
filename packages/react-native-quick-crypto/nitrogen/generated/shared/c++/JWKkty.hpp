///
/// JWKkty.hpp
/// This file was generated by nitrogen. DO NOT MODIFY THIS FILE.
/// https://github.com/mrousavy/nitro
/// Copyright © 2024 Marc Rousavy @ Margelo
///

#pragma once

#if __has_include(<NitroModules/NitroHash.hpp>)
#include <NitroModules/NitroHash.hpp>
#else
#error NitroModules cannot be found! Are you sure you installed NitroModules properly?
#endif
#if __has_include(<NitroModules/JSIConverter.hpp>)
#include <NitroModules/JSIConverter.hpp>
#else
#error NitroModules cannot be found! Are you sure you installed NitroModules properly?
#endif
#if __has_include(<NitroModules/NitroDefines.hpp>)
#include <NitroModules/NitroDefines.hpp>
#else
#error NitroModules cannot be found! Are you sure you installed NitroModules properly?
#endif

namespace margelo::nitro::crypto {

  /**
   * An enum which can be represented as a JavaScript union (JWKkty).
   */
  enum class JWKkty {
    AES      SWIFT_NAME(aes) = 0,
    RSA      SWIFT_NAME(rsa) = 1,
    EC      SWIFT_NAME(ec) = 2,
    OCT      SWIFT_NAME(oct) = 3,
  } CLOSED_ENUM;

} // namespace margelo::nitro::crypto

namespace margelo::nitro {

  using namespace margelo::nitro::crypto;

  // C++ JWKkty <> JS JWKkty (union)
  template <>
  struct JSIConverter<JWKkty> {
    static inline JWKkty fromJSI(jsi::Runtime& runtime, const jsi::Value& arg) {
      std::string unionValue = JSIConverter<std::string>::fromJSI(runtime, arg);
      switch (hashString(unionValue.c_str(), unionValue.size())) {
        case hashString("AES"): return JWKkty::AES;
        case hashString("RSA"): return JWKkty::RSA;
        case hashString("EC"): return JWKkty::EC;
        case hashString("oct"): return JWKkty::OCT;
        default: [[unlikely]]
          throw std::runtime_error("Cannot convert \"" + unionValue + "\" to enum JWKkty - invalid value!");
      }
    }
    static inline jsi::Value toJSI(jsi::Runtime& runtime, JWKkty arg) {
      switch (arg) {
        case JWKkty::AES: return JSIConverter<std::string>::toJSI(runtime, "AES");
        case JWKkty::RSA: return JSIConverter<std::string>::toJSI(runtime, "RSA");
        case JWKkty::EC: return JSIConverter<std::string>::toJSI(runtime, "EC");
        case JWKkty::OCT: return JSIConverter<std::string>::toJSI(runtime, "oct");
        default: [[unlikely]]
          throw std::runtime_error("Cannot convert JWKkty to JS - invalid value: "
                                    + std::to_string(static_cast<int>(arg)) + "!");
      }
    }
    static inline bool canConvert(jsi::Runtime& runtime, const jsi::Value& value) {
      if (!value.isString()) {
        return false;
      }
      std::string unionValue = JSIConverter<std::string>::fromJSI(runtime, value);
      switch (hashString(unionValue.c_str(), unionValue.size())) {
        case hashString("AES"):
        case hashString("RSA"):
        case hashString("EC"):
        case hashString("oct"):
          return true;
        default:
          return false;
      }
    }
  };

} // namespace margelo::nitro
