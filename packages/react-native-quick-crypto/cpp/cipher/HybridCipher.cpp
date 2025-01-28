#include <memory>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string>
#include <vector>

#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

HybridCipher::~HybridCipher() {
  if (ctx) {
    EVP_CIPHER_CTX_free(ctx);
  }
}

void
HybridCipher::init() {
  // check if args are set
  if (!args.has_value()) {
    throw std::runtime_error("CipherArgs not set");
  }
  const auto& argsRef = args.value();

  // fetch cipher
  EVP_CIPHER *cipher = EVP_CIPHER_fetch(
    nullptr,
    argsRef.cipherType.c_str(),
    nullptr
  );
  if (cipher == nullptr) {
    throw std::runtime_error("Invalid Cipher Algorithm: " + argsRef.cipherType);
  }

  // Create cipher context
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    EVP_CIPHER_free(cipher);
    throw std::runtime_error("Failed to create cipher context");
  }

  // Initialize cipher operation
  if (
    EVP_CipherInit_ex2(
      ctx,
      cipher,
      argsRef.cipherKey->data(),
      argsRef.iv->data(),
      argsRef.isCipher ? 1 : 0,
      nullptr
    ) != 1
  ) {
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    ctx = nullptr;
    throw std::runtime_error("Failed to initialize encryption");
  }

  EVP_CIPHER_free(cipher);
}

std::shared_ptr<ArrayBuffer>
HybridCipher::update(
  const std::shared_ptr<ArrayBuffer>& data
) {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  // Calculate the maximum output length
  int outLen = data->size() + EVP_MAX_BLOCK_LENGTH;
  int updateLen = 0;

  // Create a temporary buffer for the operation
  unsigned char* tempBuf = new unsigned char[outLen];

  // Perform the cipher update operation
  if (
    EVP_CipherUpdate(
      ctx,
      tempBuf,
      &updateLen,
      reinterpret_cast<const unsigned char*>(data->data()),
      data->size()
    ) != 1
  ) {
    delete[] tempBuf;
    throw std::runtime_error("Failed to update cipher");
  }

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(
    tempBuf,
    updateLen,
    [=]() { delete[] tempBuf; }
  );
}

std::shared_ptr<ArrayBuffer>
HybridCipher::final() {
  if (!ctx) {
    throw std::runtime_error("Cipher not initialized. Did you call setArgs()?");
  }

  int finalLen = 0;
  uint8_t* tempBuf = new uint8_t[EVP_MAX_BLOCK_LENGTH];

  // Finalize the encryption/decryption
  if (EVP_CipherFinal_ex(
        ctx,
        tempBuf,
        &finalLen) != 1) {
    delete[] tempBuf;
    throw std::runtime_error("Failed to finalize cipher: " +
      std::to_string(ERR_get_error()));
  }

  // Create and return a new buffer of exact size needed
  return std::make_shared<NativeArrayBuffer>(
    tempBuf,
    finalLen,
    [=]() { delete[] tempBuf; }
  );
}

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
  if (this->args.has_value()) {
    // Reset existing value if any
    this->args.reset();
  }

  // Use std::optional::emplace with direct member initialization
  this->args.emplace(CipherArgs{
    args.isCipher,
    args.cipherType,
    args.cipherKey,
    args.iv,
    args.authTagLen
  });

  init();
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
