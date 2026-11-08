#include "HybridSlhDsaKeyPair.hpp"

#include <NitroModules/ArrayBuffer.hpp>
#include <NitroModules/Dispatcher.hpp>
#include <NitroModules/JSIConverter.hpp>
#include <NitroModules/ThreadPool.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <array>
#include <stdexcept>

#include "QuickCryptoUtils.hpp"
#include "SlhDsaRawPrivateKeyValidation.hpp"

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
#define RNQC_HAS_SLH_DSA 1
#else
#define RNQC_HAS_SLH_DSA 0
#endif

namespace margelo::nitro::crypto {

using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

#if RNQC_HAS_SLH_DSA
static bool isValidSlhDsaVariant(const std::string& variant) {
  return slhDsaRawPrivateKeySize(variant) != 0;
}
#endif

facebook::jsi::Value HybridSlhDsaKeyPair::validateRawPrivateKey(facebook::jsi::Runtime& runtime, const facebook::jsi::Value&,
                                                                const facebook::jsi::Value* args, size_t argCount) {
  constexpr const char* error = "SLH-DSA raw private key validation failed";
  if (argCount != 1 || !args[0].isObject()) {
    throw facebook::jsi::JSError(runtime, error);
  }

  try {
    auto object = args[0].getObject(runtime);
    // The typed Nitro converter checks the ArrayBuffer brand only in debug builds.
    if (!object.isArrayBuffer(runtime)) {
      throw std::invalid_argument(error);
    }
    auto buffer = std::move(object).getArrayBuffer(runtime);
    const auto size = buffer.size(runtime);
    const auto variant = variant_;
    const auto expectedSize = slhDsaRawPrivateKeySize(variant);
    if (expectedSize == 0 || size != expectedSize) {
      throw std::invalid_argument(error);
    }

    // Fail before copying if this runtime cannot dispatch Promise callbacks.
    Dispatcher::getRuntimeGlobalDispatcher(runtime);
    auto validation = std::make_shared<SlhDsaRawPrivateKeyValidation>(variant, buffer.data(runtime), size);
    using Result = std::shared_ptr<ArrayBuffer>;
    using ValidationPromise = Promise<Result>;
    using Resolve = JSIConverter<std::function<void(Result)>>;
    using Reject = JSIConverter<std::function<void(std::exception_ptr)>>;
    enum class Attachment { pending, failed, ready };
    auto attachment = std::make_shared<Attachment>(Attachment::pending);
    auto promise = ValidationPromise::create();
    auto jsPromise = CommonGlobals::Promise::callConstructor(
        runtime, [promise, attachment, error](facebook::jsi::Runtime& js, const facebook::jsi::Value&,
                                              const facebook::jsi::Value* callbacks, size_t count) {
          const bool first = *attachment == Attachment::pending;
          *attachment = Attachment::failed;
          if (!first || count != 2 || !Resolve::canConvert(js, callbacks[0]) || !Reject::canConvert(js, callbacks[1])) {
            throw facebook::jsi::JSError(js, error);
          }
          auto resolve = Resolve::fromJSI(js, callbacks[0]);
          auto reject = Reject::fromJSI(js, callbacks[1]);
          promise->addOnResolvedListener(std::move(resolve));
          promise->addOnRejectedListener(std::move(reject));
          *attachment = Attachment::ready;
          return facebook::jsi::Value::undefined();
        });
    // The JS constructor catches executor errors. A returned Promise by
    // itself does not establish that a resolver and rejecter were attached.
    if (*attachment != Attachment::ready) {
      if (*attachment == Attachment::failed)
        return jsPromise;
      throw std::runtime_error(error);
    }

    try {
      ThreadPool::shared().run([validation = std::move(validation), promise]() mutable {
        Result output;
        try {
          // The worker owns a synchronous copy, never a JS-backed buffer.
          auto active = std::move(validation);
          const auto publicKey = active->validate();
          output = ArrayBuffer::copy(publicKey.data(), publicKey.size());
        } catch (...) {
          // The owned input has unwound before either callback can run.
          promise->reject(std::current_exception());
          return;
        }
        promise->resolve(std::move(output));
      });
    } catch (...) {
      validation.reset();
      try {
        throw std::runtime_error(error);
      } catch (...) {
        promise->reject(std::current_exception());
      }
    }
    return jsPromise;
  } catch (...) {
    throw facebook::jsi::JSError(runtime, error);
  }
}

// Generated conversion omits release-mode ArrayBuffer brand checks and converts
// the returned Promise after entering native code. Admit work only after both
// the input and the JavaScript Promise callbacks have been checked.
void HybridSlhDsaKeyPair::loadHybridMethods() {
  HybridSlhDsaKeyPairSpec::loadHybridMethods();
  registerHybrids(this, [](Prototype& prototype) {
    prototype.registerRawHybridMethod("validateRawPrivateKey", 1, &HybridSlhDsaKeyPair::validateRawPrivateKey);
  });
}

void HybridSlhDsaKeyPair::setVariant(const std::string& variant) {
#if !RNQC_HAS_SLH_DSA
  throw std::runtime_error("SLH-DSA requires OpenSSL 3.5+");
#else
  if (!isValidSlhDsaVariant(variant)) {
    throw std::runtime_error("Invalid SLH-DSA variant: " + variant);
  }
  variant_ = variant;
#endif
}

std::shared_ptr<Promise<void>> HybridSlhDsaKeyPair::generateKeyPair(double publicFormat, double publicType, double privateFormat,
                                                                    double privateType) {
  auto self = this->shared_cast<HybridSlhDsaKeyPair>();
  return Promise<void>::async([self, publicFormat, publicType, privateFormat, privateType]() {
    self->generateKeyPairSync(publicFormat, publicType, privateFormat, privateType);
  });
}

void HybridSlhDsaKeyPair::generateKeyPairSync(double publicFormat, double publicType, double privateFormat, double privateType) {
#if !RNQC_HAS_SLH_DSA
  throw std::runtime_error("SLH-DSA requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();

  if (variant_.empty()) {
    throw std::runtime_error("SLH-DSA variant not set. Call setVariant() first.");
  }

  publicFormat_ = static_cast<int>(publicFormat);
  publicType_ = static_cast<int>(publicType);
  privateFormat_ = static_cast<int>(privateFormat);
  privateType_ = static_cast<int>(privateType);

  pkey_.reset();

  EVP_PKEY_CTX_ptr pctx(EVP_PKEY_CTX_new_from_name(nullptr, variant_.c_str(), nullptr), EVP_PKEY_CTX_free);
  if (pctx == nullptr) {
    throw std::runtime_error("Failed to create key context for " + variant_ + ": " + getOpenSSLError());
  }

  if (EVP_PKEY_keygen_init(pctx.get()) <= 0) {
    throw std::runtime_error("Failed to initialize keygen: " + getOpenSSLError());
  }

  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_keygen(pctx.get(), &raw) <= 0) {
    throw std::runtime_error("Failed to generate SLH-DSA key pair: " + getOpenSSLError());
  }
  pkey_.reset(raw);
#endif
}

std::shared_ptr<ArrayBuffer> HybridSlhDsaKeyPair::getPublicKey() {
#if !RNQC_HAS_SLH_DSA
  throw std::runtime_error("SLH-DSA requires OpenSSL 3.5+");
#else
  checkKeyPair();

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    throw std::runtime_error("Failed to create BIO for public key export");
  }

  int result;
  if (publicFormat_ == 1) {
    result = PEM_write_bio_PUBKEY(bio, pkey_.get());
  } else {
    result = i2d_PUBKEY_bio(bio, pkey_.get());
  }

  if (result != 1) {
    BIO_free(bio);
    throw std::runtime_error("Failed to export public key: " + getOpenSSLError());
  }

  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio, &bptr);

  size_t len = bptr->length;
  auto buf = std::make_unique<uint8_t[]>(len);
  memcpy(buf.get(), bptr->data, len);

  BIO_free(bio);

  uint8_t* raw_ptr = buf.get();
  return std::make_shared<NativeArrayBuffer>(buf.release(), len, [raw_ptr]() { delete[] raw_ptr; });
#endif
}

std::shared_ptr<ArrayBuffer> HybridSlhDsaKeyPair::getPrivateKey() {
#if !RNQC_HAS_SLH_DSA
  throw std::runtime_error("SLH-DSA requires OpenSSL 3.5+");
#else
  checkKeyPair();

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) {
    throw std::runtime_error("Failed to create BIO for private key export");
  }

  int result;
  if (privateFormat_ == 1) {
    result = PEM_write_bio_PrivateKey(bio, pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr);
  } else {
    result = i2d_PKCS8PrivateKey_bio(bio, pkey_.get(), nullptr, nullptr, 0, nullptr, nullptr);
  }

  if (result != 1) {
    BIO_free(bio);
    throw std::runtime_error("Failed to export private key: " + getOpenSSLError());
  }

  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio, &bptr);

  size_t len = bptr->length;
  auto buf = std::make_unique<uint8_t[]>(len);
  memcpy(buf.get(), bptr->data, len);

  secureZero(bptr->data, bptr->length);
  BIO_free(bio);

  uint8_t* raw_ptr = buf.get();
  return std::make_shared<NativeArrayBuffer>(buf.release(), len, [raw_ptr]() { delete[] raw_ptr; });
#endif
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridSlhDsaKeyPair::sign(const std::shared_ptr<ArrayBuffer>& message) {
  auto nativeMessage = ToNativeArrayBuffer(message);
  auto self = this->shared_cast<HybridSlhDsaKeyPair>();
  return Promise<std::shared_ptr<ArrayBuffer>>::async([self, nativeMessage]() { return self->signSync(nativeMessage); });
}

std::shared_ptr<ArrayBuffer> HybridSlhDsaKeyPair::signSync(const std::shared_ptr<ArrayBuffer>& message) {
#if !RNQC_HAS_SLH_DSA
  throw std::runtime_error("SLH-DSA requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();
  checkKeyPair();

  EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (md_ctx == nullptr) {
    throw std::runtime_error("Failed to create signing context");
  }

  if (EVP_DigestSignInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey_.get()) <= 0) {
    throw std::runtime_error("Failed to initialize signing: " + getOpenSSLError());
  }

  size_t sig_len = 0;
  if (EVP_DigestSign(md_ctx.get(), nullptr, &sig_len, message->data(), message->size()) <= 0) {
    throw std::runtime_error("Failed to calculate signature size: " + getOpenSSLError());
  }

  auto sig = std::make_unique<uint8_t[]>(sig_len);

  if (EVP_DigestSign(md_ctx.get(), sig.get(), &sig_len, message->data(), message->size()) <= 0) {
    throw std::runtime_error("Failed to sign message: " + getOpenSSLError());
  }

  uint8_t* raw_ptr = sig.get();
  return std::make_shared<NativeArrayBuffer>(sig.release(), sig_len, [raw_ptr]() { delete[] raw_ptr; });
#endif
}

std::shared_ptr<Promise<bool>> HybridSlhDsaKeyPair::verify(const std::shared_ptr<ArrayBuffer>& signature,
                                                           const std::shared_ptr<ArrayBuffer>& message) {
  auto nativeSignature = ToNativeArrayBuffer(signature);
  auto nativeMessage = ToNativeArrayBuffer(message);
  auto self = this->shared_cast<HybridSlhDsaKeyPair>();
  return Promise<bool>::async([self, nativeSignature, nativeMessage]() { return self->verifySync(nativeSignature, nativeMessage); });
}

bool HybridSlhDsaKeyPair::verifySync(const std::shared_ptr<ArrayBuffer>& signature, const std::shared_ptr<ArrayBuffer>& message) {
#if !RNQC_HAS_SLH_DSA
  throw std::runtime_error("SLH-DSA requires OpenSSL 3.5+");
#else
  clearOpenSSLErrors();
  checkKeyPair();

  EVP_MD_CTX_ptr md_ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (md_ctx == nullptr) {
    throw std::runtime_error("Failed to create verify context");
  }

  if (EVP_DigestVerifyInit(md_ctx.get(), nullptr, nullptr, nullptr, pkey_.get()) <= 0) {
    throw std::runtime_error("Failed to initialize verification: " + getOpenSSLError());
  }

  int result = EVP_DigestVerify(md_ctx.get(), signature->data(), signature->size(), message->data(), message->size());

  if (result < 0) {
    throw std::runtime_error("Verification error: " + getOpenSSLError());
  }

  return result == 1;
#endif
}

void HybridSlhDsaKeyPair::checkKeyPair() {
  if (!pkey_) {
    throw std::runtime_error("Key pair not initialized");
  }
}

} // namespace margelo::nitro::crypto
