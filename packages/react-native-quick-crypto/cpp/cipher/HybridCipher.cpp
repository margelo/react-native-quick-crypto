#include <memory>
#include <string>
#include <vector>
#include <openssl/evp.h>

#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

HybridCipher::~HybridCipher() {
  if (this->ctx) {
    EVP_CIPHER_CTX_free(this->ctx);
  }
  if (this->cipher) {
    EVP_CIPHER_free(this->cipher);
  }
}

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

  // fetch cipher
  this->cipher = EVP_CIPHER_fetch(
    nullptr,
    args.cipherType.c_str(),
    nullptr
  );
  if (cipher == nullptr) {
    throw std::runtime_error("Invalid Cipher Algorithm: " + args.cipherType);
  }

  // Create cipher context
  this->ctx = EVP_CIPHER_CTX_new();
  if (!this->ctx) {
    throw std::runtime_error("Failed to create cipher context");
  }

  // Initialize cipher operation
  if (
    EVP_CipherInit_ex2(
      this->ctx,
      this->cipher,
      this->args->cipherKey->data(),
      this->args->iv->data(),
      this->args->isCipher ? 1 : 0,
      nullptr
    ) != 1
  ) {
    EVP_CIPHER_CTX_free(this->ctx);
    this->ctx = nullptr;
    throw std::runtime_error("Failed to initialize encryption");
  }
}

void collect_ciphers(EVP_CIPHER *cipher, void *arg) {
  auto ciphers = static_cast<std::vector<std::string>*>(arg);
  const char* name = EVP_CIPHER_get0_name(cipher);
  if (name != nullptr) {
    ciphers->push_back(name);
  }
}
std::vector<std::string>
HybridCipher::getSupportedCiphers() {
  std::vector<std::string> ciphers;

  EVP_CIPHER_do_all_provided(
    nullptr, // nullptr is default library context
    collect_ciphers,
    &ciphers
  );

  return ciphers;
}

} // namespace margelo::nitro::crypto
