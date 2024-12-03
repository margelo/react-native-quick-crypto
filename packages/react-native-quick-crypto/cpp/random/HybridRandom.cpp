#include <openssl/err.h>
#include <openssl/rand.h>

#include "HybridRandom.hpp"
#include "Utils.hpp"


size_t checkSize(double size) {
  if (!CheckIsUint32(size)) {
    throw std::runtime_error("size must be uint32");
  }
  if (static_cast<uint32_t>(size) > pow(2, 31) - 1) {
    throw std::runtime_error("size must be less than 2^31 - 1");
  }
  return static_cast<size_t>(size);
}

size_t checkOffset(double size, double offset) {
  if (!CheckIsUint32(offset)) {
    throw std::runtime_error("offset must be uint32");
  }
  if (offset > size) {
    throw std::runtime_error("offset must be less than size");
  }
  return static_cast<size_t>(offset);
}


namespace margelo::nitro::crypto {

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>>
HybridRandom::randomFill(const std::shared_ptr<ArrayBuffer>& buffer,
                         double dOffset,
                         double dSize) {
  // get owned NativeArrayBuffer before passing to sync function
  auto nativeBuffer = ToNativeArrayBuffer(buffer);

  return Promise<std::shared_ptr<ArrayBuffer>>::async(
    [this, nativeBuffer, dOffset, dSize]() {
      return this->randomFillSync(nativeBuffer, dOffset, dSize);
    }
  );
};

std::shared_ptr<ArrayBuffer>
HybridRandom::randomFillSync(const std::shared_ptr<ArrayBuffer>& buffer,
                             double dOffset,
                             double dSize) {
  size_t size = checkSize(dSize);
  size_t offset = checkOffset(dSize, dOffset);
  uint8_t* data = buffer.get()->data();
  if (RAND_bytes(data + offset, (int)size) != 1) {
    throw std::runtime_error("error calling RAND_bytes" +
      std::to_string(ERR_get_error()));
  }
  return buffer;
};

} // namespace margelo::nitro::crypto
