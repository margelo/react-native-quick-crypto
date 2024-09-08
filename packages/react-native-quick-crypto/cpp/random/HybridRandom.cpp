#include "HybridRandom.hpp"

#include <openssl/err.h>
#include <openssl/rand.h>

namespace margelo::crypto {

using namespace margelo::nitro;
using namespace margelo::nitro::crypto;

std::future<std::shared_ptr<ArrayBuffer>> HybridRandom::randomFill(const std::shared_ptr<ArrayBuffer>& buffer, double dOffset,
                                                                   double dSize) {
  size_t size = checkSize(dSize);
  // copy the JSArrayBuffer that we do not own into a NativeArrayBuffer that we do own, before passing to sync function
  uint8_t* data = new uint8_t[size];
  memcpy(data, buffer.get()->data(), size);
  std::shared_ptr<ArrayBuffer> nativeBuffer = std::make_shared<NativeArrayBuffer>(data, size, nullptr);

  return std::async(std::launch::async,
                    [this, nativeBuffer, dOffset, dSize]() { return this->randomFillSync(nativeBuffer, dOffset, dSize); });
};

std::shared_ptr<ArrayBuffer> HybridRandom::randomFillSync(const std::shared_ptr<ArrayBuffer>& buffer, double dOffset, double dSize) {
  size_t size = checkSize(dSize);
  size_t offset = checkOffset(dSize, dOffset);
  uint8_t* data = buffer.get()->data();

  if (RAND_bytes(data + offset, (int)size) != 1) {
    throw std::runtime_error("error calling RAND_bytes" + std::to_string(ERR_get_error()));
  }
  return std::make_shared<NativeArrayBuffer>(data, size, nullptr);
};

} // namespace margelo::crypto
