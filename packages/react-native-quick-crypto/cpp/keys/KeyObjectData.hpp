#include <memory>

#include <NitroModules/ArrayBuffer.hpp>

#include "KFormatType.hpp"
#include "KeyEncoding.hpp"
#include "KeyType.hpp"
#include "Utils.hpp"
#include "ncrypto.h"

namespace margelo::nitro::crypto {

class KeyObjectData final {
 public:
  static KeyObjectData CreateSecret(std::shared_ptr<ArrayBuffer> key);

  static KeyObjectData CreateAsymmetric(KeyType type, ncrypto::EVPKeyPointer&& pkey);

  KeyObjectData(std::nullptr_t = nullptr);

  inline operator bool() const {
    return data_ != nullptr;
  }

  KeyType GetKeyType() const;

  // These functions allow unprotected access to the raw key material and should
  // only be used to implement cryptographic operations requiring the key.
  const ncrypto::EVPKeyPointer& GetAsymmetricKey() const;
  std::shared_ptr<ArrayBuffer> GetSymmetricKey() const;
  size_t GetSymmetricKeySize() const;

  static KeyObjectData GetPublicOrPrivateKey(std::shared_ptr<ArrayBuffer> key, std::optional<KFormatType> format,
                                             std::optional<KeyEncoding> type,
                                             const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase);

  static KeyObjectData GetPrivateKey(std::shared_ptr<ArrayBuffer> key, std::optional<KFormatType> format, std::optional<KeyEncoding> type,
                                     const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase, bool isPublic);

  inline KeyObjectData addRef() const {
    return KeyObjectData(key_type_, data_);
  }

  inline KeyObjectData addRefWithType(KeyType type) const {
    return KeyObjectData(type, data_);
  }

 private:
  explicit KeyObjectData(std::shared_ptr<ArrayBuffer> symmetric_key);
  explicit KeyObjectData(KeyType type, ncrypto::EVPKeyPointer&& pkey);

  //   static KeyObjectData GetParsedKey(KeyType type,
  //     Environment* env,
  //     ncrypto::EVPKeyPointer&& pkey,
  //     ParseKeyResult ret,
  //     const char* default_msg);

  KeyType key_type_;

  struct Data {
    const std::shared_ptr<ArrayBuffer> symmetric_key;
    const ncrypto::EVPKeyPointer asymmetric_key;
    explicit Data(std::shared_ptr<ArrayBuffer> symmetric_key) : symmetric_key(std::move(symmetric_key)) {}
    explicit Data(ncrypto::EVPKeyPointer asymmetric_key) : asymmetric_key(std::move(asymmetric_key)) {}
  };
  std::shared_ptr<Data> data_;

  KeyObjectData(KeyType type, std::shared_ptr<Data> data) : key_type_(type), data_(data) {}
};

} // namespace margelo::nitro::crypto
