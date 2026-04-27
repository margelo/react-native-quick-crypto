#pragma once

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>
#include <type_traits>
#include <vector>

#include "Macros.hpp"
#include <NitroModules/ArrayBuffer.hpp>

namespace margelo::nitro::crypto {

// Function to get the last OpenSSL error message and clear the error stack
inline std::string getOpenSSLError() {
  unsigned long errCode = ERR_get_error();
  if (errCode == 0) {
    return "";
  }
  char errStr[256];
  ERR_error_string_n(errCode, errStr, sizeof(errStr));
  // Clear any remaining errors from the error stack to prevent pollution
  ERR_clear_error();
  return std::string(errStr);
}

// Function to clear OpenSSL error stack without getting error message
inline void clearOpenSSLErrors() {
  ERR_clear_error();
}

// copy a JSArrayBuffer that we do not own into a NativeArrayBuffer that we do own
inline std::shared_ptr<margelo::nitro::NativeArrayBuffer> ToNativeArrayBuffer(const std::shared_ptr<margelo::nitro::ArrayBuffer>& buffer) {
  size_t bufferSize = buffer.get()->size();
  uint8_t* data = new uint8_t[bufferSize];
  memcpy(data, buffer.get()->data(), bufferSize);
  return std::make_shared<margelo::nitro::NativeArrayBuffer>(data, bufferSize, [=]() { delete[] data; });
}

inline std::shared_ptr<margelo::nitro::NativeArrayBuffer> ToNativeArrayBuffer(std::string str) {
  size_t size = str.size();
  uint8_t* data = new uint8_t[size];
  memcpy(data, str.data(), size);
  return std::make_shared<margelo::nitro::NativeArrayBuffer>(data, size, [=]() { delete[] data; });
}

inline std::shared_ptr<margelo::nitro::NativeArrayBuffer> ToNativeArrayBuffer(const std::vector<uint8_t>& vec) {
  size_t size = vec.size();
  uint8_t* data = new uint8_t[size];
  memcpy(data, vec.data(), size);
  return std::make_shared<margelo::nitro::NativeArrayBuffer>(data, size, [=]() { delete[] data; });
}

inline std::shared_ptr<margelo::nitro::NativeArrayBuffer> ToNativeArrayBuffer(const uint8_t* ptr, size_t size) {
  uint8_t* data = new uint8_t[size];
  memcpy(data, ptr, size);
  return std::make_shared<margelo::nitro::NativeArrayBuffer>(data, size, [=]() { delete[] data; });
}

inline bool CheckIsUint32(double value) {
  return (value >= std::numeric_limits<uint32_t>::lowest() && value <= std::numeric_limits<uint32_t>::max());
}

inline bool CheckIsInt32(double value) {
  return (value >= std::numeric_limits<int32_t>::lowest() && value <= std::numeric_limits<int32_t>::max());
}

// Validate a JS-side `double` intended to be an unsigned integer in
// [minValue, maxValue], then cast it to T. Rejects NaN, +/-Infinity, negative
// values, and fractional values BEFORE the cast — `static_cast<uint32_t>(NaN)`
// and friends are undefined behavior in C++, and the audit found ~20 sites
// that did the cast naked. Throws `std::runtime_error` carrying `paramName`
// on any failure so JS callers see a descriptive, actionable message.
//
// The helper is templated so callers pick the destination type
// (uint32_t, uint64_t, size_t, ...). T must be an unsigned integer type.
template <typename T>
T validateUInt(double value, const char* paramName, T minValue = 0, T maxValue = std::numeric_limits<T>::max()) {
  static_assert(std::is_integral_v<T> && std::is_unsigned_v<T>, "validateUInt: T must be an unsigned integer type");

  if (std::isnan(value)) {
    throw std::runtime_error(std::string(paramName) + " must be a finite number, got NaN");
  }
  if (std::isinf(value)) {
    throw std::runtime_error(std::string(paramName) + std::string(" must be a finite number, got ") +
                             (value > 0 ? "+Infinity" : "-Infinity"));
  }
  if (value < 0) {
    throw std::runtime_error(std::string(paramName) + " must be non-negative, got " + std::to_string(value));
  }
  if (value != std::floor(value)) {
    throw std::runtime_error(std::string(paramName) + " must be an integer, got " + std::to_string(value));
  }
  if (value < static_cast<double>(minValue) || value > static_cast<double>(maxValue)) {
    throw std::runtime_error(std::string(paramName) + " out of range [" + std::to_string(minValue) + ", " + std::to_string(maxValue) +
                             "], got " + std::to_string(value));
  }
  return static_cast<T>(value);
}

// Securely zero a memory range using OPENSSL_cleanse, which the compiler is
// guaranteed not to optimize away even when the buffer is about to leave
// scope. Use this for any memory that held secrets — keys, derived bits,
// shared secrets, plaintext, PEM/DER private-key strings, IV/nonce material.
//
// Plain std::memset is unsafe for this purpose: under -O2 the compiler will
// see that the memset writes are dead (the memory is freed or going out of
// scope right after) and elide them, leaving the secret on the heap.
//
// Overloads cover the common shapes: raw pointer + size, vector, string,
// fixed-size array. The audit found ~30 sites that need this — XSalsa20,
// XChaCha20-Poly1305, all KDFs, DH/ECDH shared secrets, RSA/EC/Ed/DSA DER
// private-key strings — and they get swept in Phase 2.
inline void secureZero(void* ptr, std::size_t size) {
  if (ptr != nullptr && size > 0) {
    OPENSSL_cleanse(ptr, size);
  }
}

inline void secureZero(std::vector<uint8_t>& vec) {
  secureZero(vec.data(), vec.size());
}

inline void secureZero(std::string& s) {
  if (!s.empty()) {
    secureZero(s.data(), s.size());
  }
}

template <std::size_t N>
inline void secureZero(uint8_t (&arr)[N]) {
  secureZero(static_cast<void*>(arr), N);
}

// Function to convert a string to lowercase
inline std::string toLower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

inline const EVP_MD* getDigestByName(const std::string& algorithm) {
  std::string algo = toLower(algorithm);

  // Strip legacy RSA- prefix (e.g. rsa-sha256 -> sha256) for Node.js compat
  if (algo.size() > 4 && algo.compare(0, 4, "rsa-") == 0) {
    algo = algo.substr(4);
  }

  if (algo == "sha1" || algo == "sha-1") {
    return EVP_sha1();
  } else if (algo == "sha224" || algo == "sha-224") {
    return EVP_sha224();
  } else if (algo == "sha256" || algo == "sha-256") {
    return EVP_sha256();
  } else if (algo == "sha384" || algo == "sha-384") {
    return EVP_sha384();
  } else if (algo == "sha512" || algo == "sha-512") {
    return EVP_sha512();
  } else if (algo == "sha3-224") {
    return EVP_sha3_224();
  } else if (algo == "sha3-256") {
    return EVP_sha3_256();
  } else if (algo == "sha3-384") {
    return EVP_sha3_384();
  } else if (algo == "sha3-512") {
    return EVP_sha3_512();
  } else if (algo == "ripemd160" || algo == "ripemd-160") {
    return EVP_ripemd160();
  }
  throw std::runtime_error("Unsupported hash algorithm: " + algorithm);
}

// Build an EVP_PKEY from EC curve name + public key octets + optional private key BIGNUM.
// Uses OSSL_PARAM_BLD + EVP_PKEY_fromdata (OpenSSL 3.x, no deprecated EC_KEY APIs).
// Caller owns the returned EVP_PKEY*.
EVP_PKEY* createEcEvpPkey(const char* group_name, const uint8_t* pub_oct, size_t pub_len, const BIGNUM* priv_bn = nullptr);

} // namespace margelo::nitro::crypto
