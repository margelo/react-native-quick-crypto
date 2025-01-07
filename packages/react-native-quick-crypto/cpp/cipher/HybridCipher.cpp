#include <memory>

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
HybridCipher::copy() {}

bool
HybridCipher::setAAD(
  const std::shared_ptr<ArrayBuffer>& data,
  std::optional<double> plaintextLength
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

void
HybridCipher::setArgs(
  const CipherArgs& args
) {
  this->args = args;
  init();
}

void
HybridCipher::init() {
  // check if args are set
  if (!args.has_value()) {
    throw std::runtime_error("CipherArgs not set");
  }
  auto args = this->args.value();

  // check if cipherType is valid
  const EVP_CIPHER *const cipher = EVP_get_cipherbyname(args.cipherType.c_str());
  if (cipher == nullptr) {
    throw std::runtime_error("Invalid Cipher Algorithm: " + args.cipherType);
  }
}

} // namespace margelo::nitro::crypto
