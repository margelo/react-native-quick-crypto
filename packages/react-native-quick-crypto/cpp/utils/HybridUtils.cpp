#include "HybridUtils.hpp"

#include <limits>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>

#include "QuickCryptoUtils.hpp"

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
    if (hex.length() % 2 != 0) {
      throw std::runtime_error("Invalid hex string length");
    }
    std::vector<uint8_t> result;
    result.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
      int hi = hexCharToVal(hex[i]);
      int lo = hexCharToVal(hex[i + 1]);
      if (hi < 0 || lo < 0) {
        throw std::runtime_error("Invalid hex character");
      }
      result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return result;
  }

  std::string encodeBase64(const uint8_t* data, size_t len) {
    if (len > static_cast<size_t>(std::numeric_limits<int>::max())) {
      throw std::runtime_error("Input too large for base64 encoding");
    }
    size_t encodedLen = ((len + 2) / 3) * 4;
    std::string result(encodedLen + 1, '\0');
    int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(result.data()), data, static_cast<int>(len));
    if (written < 0) {
      throw std::runtime_error("Base64 encoding failed");
    }
    result.resize(static_cast<size_t>(written));
    return result;
  }

  std::vector<uint8_t> decodeBase64(const std::string& b64) {
    if (b64.length() > static_cast<size_t>(std::numeric_limits<int>::max())) {
      throw std::runtime_error("Input too large for base64 decoding");
    }
    size_t maxLen = ((b64.length() + 3) / 4) * 3;
    std::vector<uint8_t> result(maxLen);
    int written = EVP_DecodeBlock(result.data(), reinterpret_cast<const unsigned char*>(b64.data()), static_cast<int>(b64.length()));
    if (written < 0) {
      throw std::runtime_error("Base64 decoding failed");
    }
    // EVP_DecodeBlock doesn't account for padding — trim trailing zeros from padding
    size_t padding = 0;
    if (b64.length() >= 1 && b64[b64.length() - 1] == '=')
      padding++;
    if (b64.length() >= 2 && b64[b64.length() - 2] == '=')
      padding++;
    result.resize(static_cast<size_t>(written) - padding);
    return result;
  }

  std::string encodeBase64Url(const uint8_t* data, size_t len) {
    std::string b64 = encodeBase64(data, len);
    for (auto& c : b64) {
      if (c == '+')
        c = '-';
      else if (c == '/')
        c = '_';
    }
    // Remove trailing '=' padding
    while (!b64.empty() && b64.back() == '=') {
      b64.pop_back();
    }
    return b64;
  }

  std::vector<uint8_t> decodeBase64Url(const std::string& b64url) {
    std::string b64 = b64url;
    for (auto& c : b64) {
      if (c == '-')
        c = '+';
      else if (c == '_')
        c = '/';
    }
    // Add back padding
    while (b64.length() % 4 != 0) {
      b64.push_back('=');
    }
    return decodeBase64(b64);
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
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
      uint8_t byte = data[i];
      if (byte < 0x80) {
        result.push_back(static_cast<char>(byte));
      } else {
        // Latin1 byte 0x80-0xFF → UTF-8 two-byte sequence
        result.push_back(static_cast<char>(0xC0 | (byte >> 6)));
        result.push_back(static_cast<char>(0x80 | (byte & 0x3F)));
      }
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

std::string HybridUtils::bufferToString(const std::shared_ptr<ArrayBuffer>& buffer, const std::string& encoding) {
  const auto* data = reinterpret_cast<const uint8_t*>(buffer->data());
  size_t len = buffer->size();

  if (encoding == "hex") {
    return encodeHex(data, len);
  }
  if (encoding == "base64") {
    return encodeBase64(data, len);
  }
  if (encoding == "base64url") {
    return encodeBase64Url(data, len);
  }
  if (encoding == "utf8" || encoding == "utf-8") {
    return std::string(reinterpret_cast<const char*>(data), len);
  }
  if (encoding == "latin1" || encoding == "binary") {
    return encodeLatin1(data, len);
  }
  if (encoding == "ascii") {
    std::string result(reinterpret_cast<const char*>(data), len);
    for (auto& c : result) {
      c &= 0x7F;
    }
    return result;
  }
  throw std::runtime_error("Unsupported encoding: " + encoding);
}

std::shared_ptr<ArrayBuffer> HybridUtils::stringToBuffer(const std::string& str, const std::string& encoding) {
  if (encoding == "hex") {
    auto decoded = decodeHex(str);
    return ToNativeArrayBuffer(decoded);
  }
  if (encoding == "base64") {
    auto decoded = decodeBase64(str);
    return ToNativeArrayBuffer(decoded);
  }
  if (encoding == "base64url") {
    auto decoded = decodeBase64Url(str);
    return ToNativeArrayBuffer(decoded);
  }
  if (encoding == "utf8" || encoding == "utf-8") {
    return ToNativeArrayBuffer(str);
  }
  if (encoding == "latin1" || encoding == "binary") {
    auto decoded = decodeLatin1(str);
    return ToNativeArrayBuffer(decoded);
  }
  if (encoding == "ascii") {
    auto decoded = decodeLatin1(str);
    for (auto& b : decoded) {
      b &= 0x7F;
    }
    return ToNativeArrayBuffer(decoded);
  }
  throw std::runtime_error("Unsupported encoding: " + encoding);
}

} // namespace margelo::nitro::crypto
