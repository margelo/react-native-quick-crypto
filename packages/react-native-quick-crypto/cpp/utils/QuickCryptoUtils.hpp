#pragma once

#include <algorithm>
#include <cctype>
#include <limits>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>
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
