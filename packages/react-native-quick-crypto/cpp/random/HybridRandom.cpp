#include "HybridRandom.hpp"

#include <openssl/err.h>
#include <openssl/rand.h>

namespace margelo::nitro::crypto {

std::future<std::shared_ptr<ArrayBuffer>>
HybridRandom::randomFill(const std::shared_ptr<ArrayBuffer>& buffer,
                         double dOffset,
                         double dSize) {
  size_t bufferSize = buffer.get()->size();
  // copy the JSArrayBuffer that we do not own into a NativeArrayBuffer that we
  // do own, before passing to sync function
  uint8_t* data = new uint8_t[bufferSize];
  memcpy(data, buffer.get()->data(), bufferSize);
  std::shared_ptr<NativeArrayBuffer> nativeBuffer =
    // std::make_shared<NativeArrayBuffer>(data, bufferSize, nullptr);
    std::make_shared<NativeArrayBuffer>(data, bufferSize, [=]() { delete[] data; });

  return std::async(std::launch::async,
                    [this, nativeBuffer, dOffset, dSize]() {
                      return this->randomFillSync(nativeBuffer, dOffset, dSize);
                    });
};

std::shared_ptr<ArrayBuffer>
HybridRandom::randomFillSync(const std::shared_ptr<ArrayBuffer>& buffer,
                             double dOffset,
                             double dSize) {
  // size_t bufferSize = buffer.get()->size();
  size_t size = checkSize(dSize);
  size_t offset = checkOffset(dSize, dOffset);
  uint8_t* data = buffer.get()->data();

  // printData(0, data, bufferSize);
  if (RAND_bytes(data + offset, (int)size) != 1) {
    throw std::runtime_error("error calling RAND_bytes" +
      std::to_string(ERR_get_error()));
  }
  // printData(1, data, bufferSize);
  return std::make_shared<NativeArrayBuffer>(data, size, nullptr);
};

} // namespace margelo::nitro::crypto
