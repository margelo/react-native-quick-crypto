///
/// KFormatType.hpp
/// This file was generated by nitrogen. DO NOT MODIFY THIS FILE.
/// https://github.com/mrousavy/nitro
/// Copyright © 2025 Marc Rousavy @ Margelo
///

#pragma once

#include <cmath>
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
   * An enum which can be represented as a JavaScript enum (KFormatType).
   */
  enum class KFormatType {
    KKEYFORMATDER      SWIFT_NAME(kkeyformatder) = 0,
    KKEYFORMATPEM      SWIFT_NAME(kkeyformatpem) = 1,
    KKEYFORMATJWK      SWIFT_NAME(kkeyformatjwk) = 2,
  } CLOSED_ENUM;

} // namespace margelo::nitro::crypto

namespace margelo::nitro {

  using namespace margelo::nitro::crypto;

  // C++ KFormatType <> JS KFormatType (enum)
  template <>
  struct JSIConverter<KFormatType> {
    static inline KFormatType fromJSI(jsi::Runtime& runtime, const jsi::Value& arg) {
      int enumValue = JSIConverter<int>::fromJSI(runtime, arg);
      return static_cast<KFormatType>(enumValue);
    }
    static inline jsi::Value toJSI(jsi::Runtime& runtime, KFormatType arg) {
      int enumValue = static_cast<int>(arg);
      return JSIConverter<int>::toJSI(runtime, enumValue);
    }
    static inline bool canConvert(jsi::Runtime&, const jsi::Value& value) {
      if (!value.isNumber()) {
        return false;
      }
      double integer;
      double fraction = modf(value.getNumber(), &integer);
      if (fraction != 0.0) {
        // It is some kind of floating point number - our enums are ints.
        return false;
      }
      // Check if we are within the bounds of the enum.
      return integer >= 0 && integer <= 2;
    }
  };

} // namespace margelo::nitro
