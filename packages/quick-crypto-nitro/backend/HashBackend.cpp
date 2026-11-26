#include "HashBackend.hpp"
#include "../cpp/internal/HashContext.hpp"

namespace margelo::quickcrypto {

HashBackend::HashBackend(const std::string& algorithm) : context(createDigestContext(algorithm)) {}

void HashBackend::update(const uint8_t* data, size_t length) {
  if (!context) {
    throw std::logic_error("Digest already called");
  }
  updateDigest(context.get(), data, length);
}

std::vector<uint8_t> HashBackend::digest() {
  if (!context) {
    throw std::logic_error("Digest already called");
  }
  const int length = EVP_MD_CTX_get_size(context.get());
  if (length <= 0) {
    throw std::runtime_error("Expected a fixed-length digest");
  }
  std::vector<uint8_t> output(length);
  auto active = std::move(context);
  const auto written = finishDigest(active.get(), output.data());
  if (written != output.size()) {
    throw std::runtime_error("Unexpected hash digest length");
  }
  return output;
}

} // namespace margelo::quickcrypto
