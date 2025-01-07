#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

std::shared_ptr<ArrayBuffer>
HybridCipher::update(
  const std::shared_ptr<ArrayBuffer>& data
) {
  return nullptr;
}

std::shared_ptr<ArrayBuffer>
HybridCipher::final() {
  return nullptr;
}

void
HybridCipher::copy() {

}

bool
HybridCipher::setAAD(
  const std::shared_ptr<ArrayBuffer>& data,
  const std::optional<double>& plaintextLength
) {
  return false;
}

bool
HybridCipher::setAutoPadding(
  bool autoPad
) {
  return false;
}

bool
HybridCipher::setAuthTag(
  const std::shared_ptr<ArrayBuffer>& tag
) {
  return false;
}

std::shared_ptr<ArrayBuffer>
HybridCipher::getAuthTag() {
  return nullptr;
}

} // namespace margelo::nitro::crypto