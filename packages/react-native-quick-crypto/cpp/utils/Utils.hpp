#pragma once

#include <algorithm>
#include <cctype>
#include <limits>
#include <string>
#include <openssl/err.h>

#include <NitroModules/ArrayBuffer.hpp>

namespace margelo::nitro::crypto {

// Function to get the last OpenSSL error message
inline std::string getOpenSSLError() {
    unsigned long errCode = ERR_get_error();
    if (errCode == 0) {
        return "";
    }
    char errStr[256];
    ERR_error_string_n(errCode, errStr, sizeof(errStr));
    return std::string(errStr);
}

// copy a JSArrayBuffer that we do not own into a NativeArrayBuffer that we do own
inline std::shared_ptr<margelo::nitro::NativeArrayBuffer> ToNativeArrayBuffer(const std::shared_ptr<margelo::nitro::ArrayBuffer>& buffer) {
  size_t bufferSize = buffer.get()->size();
  uint8_t* data = new uint8_t[bufferSize];
  memcpy(data, buffer.get()->data(), bufferSize);
  return std::make_shared<margelo::nitro::NativeArrayBuffer>(data, bufferSize, [=]() { delete[] data; });
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

} // namespace margelo::nitro::crypto
