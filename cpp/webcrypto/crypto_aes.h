#ifndef crypto_aes_h
#define crypto_aes_h

#include <jsi/jsi.h>

#include "MGLKeys.h"
#ifdef ANDROID
#include "Utils/MGLUtils.h"
#else
#include "MGLUtils.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

constexpr size_t kAesBlockSize = 16;
constexpr unsigned kNoAuthTagLength = static_cast<unsigned>(-1);
constexpr const char* kDefaultWrapIV = "\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6";

#define VARIANTS(V)                                                           \
  V(CTR_128, AES_CTR_Cipher)                                                  \
  V(CTR_192, AES_CTR_Cipher)                                                  \
  V(CTR_256, AES_CTR_Cipher)                                                  \
  V(CBC_128, AES_Cipher)                                                      \
  V(CBC_192, AES_Cipher)                                                      \
  V(CBC_256, AES_Cipher)                                                      \
  V(GCM_128, AES_Cipher)                                                      \
  V(GCM_192, AES_Cipher)                                                      \
  V(GCM_256, AES_Cipher)                                                      \
  V(KW_128, AES_Cipher)                                                       \
  V(KW_192, AES_Cipher)                                                       \
  V(KW_256, AES_Cipher)

enum AESKeyVariant {
#define V(name, _) kKeyVariantAES_ ## name,
  VARIANTS(V)
#undef V
};

enum class WebCryptoCipherStatus {
  OK,
  INVALID_KEY_TYPE,
  FAILED
};

struct AESCipherConfig final {
    enum Mode {
    kEncrypt,
    kDecrypt,
    // kWrapKey,
    // kUnwrapKey,
  };

  Mode mode;
  AESKeyVariant variant;
  std::shared_ptr<KeyObjectData> key;
  ByteSource data;
  const EVP_CIPHER* cipher;
  ByteSource iv;  // Used for both iv or counter
  size_t length;
  ByteSource tag;  // Used only for authenticated modes (GCM)
  ByteSource additional_data;

  AESCipherConfig() = default;

  // AESCipherConfig(AESCipherConfig&& other) noexcept;

  // AESCipherConfig& operator=(AESCipherConfig&& other) noexcept;

  // void MemoryInfo(MemoryTracker* tracker) const override;
  // SET_MEMORY_INFO_NAME(AESCipherConfig)
  // SET_SELF_SIZE(AESCipherConfig)
};

class AESCipher {
 public:
  AESCipher() {}
  AESCipherConfig GetParamsFromJS(jsi::Runtime &rt, const jsi::Value *args);
  WebCryptoCipherStatus DoCipher(const AESCipherConfig &params, ByteSource *out);
};

}  // namespace margelo

#endif  // crypto_aes_h
