#include "HybridUtils.hpp"

#include <NitroModules/JSIConverter+ArrayBuffer.hpp>
#include <bit>
#include <cstring>
#include <openssl/crypto.h>
#include <stdexcept>
#include <string>
#include <vector>

#include "QuickCryptoUtils.hpp"
#include "simdutf.h"

namespace margelo::nitro::crypto {

namespace {

  constexpr char kHexChars[] = "0123456789abcdef";

  int hexCharToVal(char c) {
    if (c >= '0' && c <= '9')
      return c - '0';
    if (c >= 'a' && c <= 'f')
      return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
      return c - 'A' + 10;
    return -1;
  }

  std::string encodeHex(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
      result.push_back(kHexChars[data[i] >> 4]);
      result.push_back(kHexChars[data[i] & 0x0F]);
    }
    return result;
  }

  std::vector<uint8_t> decodeHex(const std::string& hex) {
    std::vector<uint8_t> result;
    result.reserve(hex.length() / 2);
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
      int hi = hexCharToVal(hex[i]);
      int lo = hexCharToVal(hex[i + 1]);
      if (hi < 0 || lo < 0) {
        break;
      }
      result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return result;
  }

  std::string encodeBase64(const uint8_t* data, size_t len) {
    if (len == 0) {
      return {};
    }

    size_t encodedLen = simdutf::base64_length_from_binary(len, simdutf::base64_default);
    std::string result(encodedLen, '\0');
    simdutf::binary_to_base64(reinterpret_cast<const char*>(data), len, result.data(), simdutf::base64_default);
    return result;
  }

  std::vector<uint8_t> decodeBase64(facebook::jsi::Runtime& runtime, const facebook::jsi::String& str) {
    std::string b64;

    auto chunkCallback = [&b64](bool isAscii, const void* data, size_t num) {
      if (num == 0) {
        return;
      }

      if (isAscii) {
        b64.append(reinterpret_cast<const char*>(data), num);
        return;
      }

      size_t offset = b64.size();
      b64.resize(offset + num);
      const auto* src = reinterpret_cast<const char16_t*>(data);
      auto* dst = b64.data() + offset;
      for (size_t i = 0; i < num; i++) {
        dst[i] = static_cast<char>(src[i] & 0xFFu);
      }
    };

    str.getStringData(runtime, chunkCallback);

    if (b64.empty()) {
      return {};
    }

    size_t maxLen = simdutf::maximal_binary_length_from_base64(b64.data(), b64.length());
    std::vector<uint8_t> result(maxLen);
    auto decodeResult = simdutf::base64_to_binary(b64.data(), b64.size(), reinterpret_cast<char*>(result.data()),
                                                  simdutf::base64_default_or_url_accept_garbage);
    if (decodeResult.error != simdutf::error_code::SUCCESS) {
      throw std::runtime_error("Base64 decoding failed");
    }
    result.resize(decodeResult.count);
    return result;
  }

  std::string encodeBase64Url(const uint8_t* data, size_t len) {
    if (len == 0) {
      return {};
    }

    size_t encodedLen = simdutf::base64_length_from_binary(len, simdutf::base64_url);
    std::string result(encodedLen, '\0');
    simdutf::binary_to_base64(reinterpret_cast<const char*>(data), len, result.data(), simdutf::base64_url);
    return result;
  }

  std::vector<uint8_t> decodeUtf16Le(facebook::jsi::Runtime& runtime, const facebook::jsi::String& str) {
    std::vector<uint8_t> result;

    auto chunkCallback = [&result](bool isAscii, const void* data, size_t num) {
      if (num == 0) {
        return;
      }

      size_t offset = result.size();
      result.resize(offset + (num * 2));

      auto* dst = result.data() + offset;
      if (isAscii) {
        const auto* asciiSrc = reinterpret_cast<const char*>(data);
        for (size_t i = 0; i < num; i++, dst += 2) {
          *dst = asciiSrc[i];
        }
        return;
      }

      const auto* utf16Src = reinterpret_cast<const char16_t*>(data);
      if constexpr (std::endian::native == std::endian::little && sizeof(char16_t) == 2) {
        std::memcpy(dst, utf16Src, num * 2);
        return;
      }
      for (size_t i = 0; i < num; i++) {
        const uint16_t codeUnit = static_cast<uint16_t>(utf16Src[i]);
        dst[i * 2 + 0] = static_cast<uint8_t>(codeUnit & 0xFFu);
        dst[i * 2 + 1] = static_cast<uint8_t>(codeUnit >> 8);
      }
    };

    str.getStringData(runtime, chunkCallback);
    return result;
  }

  std::vector<uint8_t> decodeLatin1(const std::string& str) {
    std::vector<uint8_t> result;
    result.reserve(str.size());
    size_t i = 0;
    while (i < str.size()) {
      auto byte = static_cast<uint8_t>(str[i]);
      uint32_t cp;
      if (byte < 0x80) {
        cp = byte;
        i += 1;
      } else if ((byte & 0xE0) == 0xC0 && i + 1 < str.size()) {
        cp = ((byte & 0x1F) << 6) | (static_cast<uint8_t>(str[i + 1]) & 0x3F);
        i += 2;
      } else if ((byte & 0xF0) == 0xE0 && i + 2 < str.size()) {
        cp = ((byte & 0x0F) << 12) | ((static_cast<uint8_t>(str[i + 1]) & 0x3F) << 6) | (static_cast<uint8_t>(str[i + 2]) & 0x3F);
        i += 3;
      } else if ((byte & 0xF8) == 0xF0 && i + 3 < str.size()) {
        cp = ((byte & 0x07) << 18) | ((static_cast<uint8_t>(str[i + 1]) & 0x3F) << 12) | ((static_cast<uint8_t>(str[i + 2]) & 0x3F) << 6) |
             (static_cast<uint8_t>(str[i + 3]) & 0x3F);
        i += 4;
      } else {
        cp = byte;
        i += 1;
      }
      result.push_back(static_cast<uint8_t>(cp & 0xFF));
    }
    return result;
  }

  std::string encodeLatin1(const uint8_t* data, size_t len) {
    if (len == 0) {
      return {};
    }

    size_t utf8Len = simdutf::utf8_length_from_latin1(reinterpret_cast<const char*>(data), len);
    std::string result(utf8Len, '\0');
    size_t written = simdutf::convert_latin1_to_utf8(reinterpret_cast<const char*>(data), len, result.data());
    if (written == 0) {
      throw std::runtime_error("Latin1 encoding failed");
    }
    return result;
  }

} // anonymous namespace

bool HybridUtils::timingSafeEqual(const std::shared_ptr<ArrayBuffer>& a, const std::shared_ptr<ArrayBuffer>& b) {
  size_t aLen = a->size();
  size_t bLen = b->size();

  if (aLen != bLen) {
    throw std::runtime_error("Input buffers must have the same byte length");
  }

  return CRYPTO_memcmp(a->data(), b->data(), aLen) == 0;
}

facebook::jsi::Value HybridUtils::bufferToJsiString(facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
                                                    const facebook::jsi::Value* args, size_t argCount) {
  // Runtime argument check from react-native-nitro-modules/cpp/core/HybridFunction.hpp
  if (argCount != 2) [[unlikely]] {
    throw facebook::jsi::JSError(runtime,
                                 "`Utils.bufferToString(...)` expected 2 arguments, but received " + std::to_string(argCount) + "!");
  }

  // Exception wrapper from react-native-nitro-modules/cpp/core/HybridFunction.hpp
  try {
    // bufferToString(buffer: ArrayBuffer, encoding: string): string; Defined in utils/conversion.ts
    auto buffer = JSIConverter<std::shared_ptr<ArrayBuffer>>::fromJSI(runtime, args[0]);
    std::string encoding = JSIConverter<std::string>::fromJSI(runtime, args[1]);

    const auto* data = reinterpret_cast<const uint8_t*>(buffer->data());
    size_t len = buffer->size();

    if (encoding == "hex") {
      return facebook::jsi::String::createFromUtf8(runtime, encodeHex(data, len));
    }
    if (encoding == "base64") {
      return facebook::jsi::String::createFromUtf8(runtime, encodeBase64(data, len));
    }
    if (encoding == "base64url") {
      return facebook::jsi::String::createFromUtf8(runtime, encodeBase64Url(data, len));
    }
    if (encoding == "utf8" || encoding == "utf-8") {
      return facebook::jsi::String::createFromUtf8(runtime, std::string(reinterpret_cast<const char*>(data), len));
    }
    if (encoding == "latin1" || encoding == "binary") {
      return facebook::jsi::String::createFromUtf8(runtime, encodeLatin1(data, len));
    }
    if (encoding == "ascii") {
      std::string result(reinterpret_cast<const char*>(data), len);
      for (auto& c : result) {
        c &= 0x7F;
      }
      return facebook::jsi::String::createFromUtf8(runtime, result);
    }
    throw std::runtime_error("Unsupported encoding: " + encoding);
  } catch (const std::exception& exception) {
    throw facebook::jsi::JSError(runtime, "Utils.bufferToString(...): " + std::string(exception.what()));
  } catch (...) {
    throw facebook::jsi::JSError(runtime,
                                 "`Utils.bufferToString(...)` threw an unknown " + TypeInfo::getCurrentExceptionName() + " error.");
  }
}

facebook::jsi::Value HybridUtils::JsiStringToBuffer(facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
                                                    const facebook::jsi::Value* args, size_t argCount) {
  // Runtime argument check from react-native-nitro-modules/cpp/core/HybridFunction.hpp
  if (argCount != 2) [[unlikely]] {
    throw facebook::jsi::JSError(runtime,
                                 "`Utils.stringToBuffer(...)` expected 2 arguments, but received " + std::to_string(argCount) + "!");
  }

  // Exception wrapper from react-native-nitro-modules/cpp/core/HybridFunction.hpp
  try {
    // stringToBuffer(str: string, encoding: string): ArrayBuffer; Defined in utils/conversion.ts
    auto str = args[0].asString(runtime);
    std::string encoding = JSIConverter<std::string>::fromJSI(runtime, args[1]);

    if (encoding == "hex") {
      auto decoded = decodeHex(str.utf8(runtime));
      return JSIConverter<std::shared_ptr<ArrayBuffer>>::toJSI(runtime, ArrayBuffer::move(std::move(decoded)));
    }
    if (encoding == "base64" || encoding == "base64url") {
      auto decoded = decodeBase64(runtime, str);
      return JSIConverter<std::shared_ptr<ArrayBuffer>>::toJSI(runtime, ArrayBuffer::move(std::move(decoded)));
    }
    if (encoding == "utf8" || encoding == "utf-8") {
      auto utf8Str = str.utf8(runtime);
      return JSIConverter<std::shared_ptr<ArrayBuffer>>::toJSI(runtime,
                                                               ArrayBuffer::copy(reinterpret_cast<const uint8_t*>(utf8Str.data()), utf8Str.size()));
    }
    if (encoding == "latin1" || encoding == "binary" || encoding == "ascii") {
      auto decoded = decodeLatin1(str.utf8(runtime));
      return JSIConverter<std::shared_ptr<ArrayBuffer>>::toJSI(runtime, ArrayBuffer::move(std::move(decoded)));
    }
    if (encoding == "utf16le") {
      auto decoded = decodeUtf16Le(runtime, str);
      return JSIConverter<std::shared_ptr<ArrayBuffer>>::toJSI(runtime, ArrayBuffer::move(std::move(decoded)));
    }
    throw std::runtime_error("Unsupported encoding: " + encoding);
  } catch (const std::exception& exception) {
    throw facebook::jsi::JSError(runtime, "Utils.stringToBuffer(...): " + std::string(exception.what()));
  } catch (...) {
    throw facebook::jsi::JSError(runtime,
                                 "`Utils.stringToBuffer(...)` threw an unknown " + TypeInfo::getCurrentExceptionName() + " error.");
  }
}

void HybridUtils::loadHybridMethods() {
  HybridUtilsSpec::loadHybridMethods();
  registerHybrids(this, [](Prototype& prototype) {
    prototype.registerRawHybridMethod("bufferToString", 2, &HybridUtils::bufferToJsiString);
    prototype.registerRawHybridMethod("stringToBuffer", 2, &HybridUtils::JsiStringToBuffer);
  });
}

} // namespace margelo::nitro::crypto
