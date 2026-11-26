#include <QuickCryptoNitro/HybridHash.hpp>

namespace margelo::nitro::quickcrypto {

HybridHash::HybridHash(const std::string& algorithm) : backend(algorithm) {}

void HybridHash::update(const ArrayBuffer& data) {
  backend.update(data.data(), data.size());
}

ArrayBuffer HybridHash::digest() {
  auto bytes = backend.digest();
  return ArrayBuffer::move(std::move(bytes));
}

} // namespace margelo::nitro::quickcrypto
