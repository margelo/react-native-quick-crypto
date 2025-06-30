#include "KeyObjectData.hpp"

namespace margelo {

KeyObjectData::KeyObjectData(std::nullptr_t)
    : key_type_(KeyType::SECRET) {}

KeyObjectData::KeyObjectData(std::shared_ptr<ArrayBuffer> symmetric_key)
    : key_type_(KeyType::SECRET),
      data_(std::make_shared<Data>(std::move(symmetric_key))) {}

KeyObjectData::KeyObjectData(KeyType type, ncrypto::EVPKeyPointer&& pkey)
    : key_type_(type), data_(std::make_shared<Data>(std::move(pkey))) {}

KeyObjectData KeyObjectData::CreateSecret(std::shared_ptr<ArrayBuffer> key) {
  return KeyObjectData(std::move(key));
}

KeyObjectData KeyObjectData::CreateAsymmetric(KeyType key_type,
                                              ncrypto::EVPKeyPointer&& pkey) {
  CHECK(pkey);
  return KeyObjectData(key_type, std::move(pkey));
}

KeyType KeyObjectData::GetKeyType() const {
  CHECK(data_);
  return key_type_;
}

const ncrypto::EVPKeyPointer& KeyObjectData::GetAsymmetricKey() const {
  CHECK_NE(key_type_, KeyType::SECRET);
  CHECK(data_);
  return data_->asymmetric_key;
}

std::shared_ptr<ArrayBuffer> KeyObjectData::GetSymmetricKey() const {
  CHECK_EQ(key_type_, KeyType::SECRET);
  CHECK(data_);
  return data_->symmetric_key;
}

size_t KeyObjectData::GetSymmetricKeySize() const {
  CHECK_EQ(key_type_, KeyType::SECRET);
  CHECK(data_);
  return data_->symmetric_key->size();
}

KeyObjectData KeyObjectData::GetPublicOrPrivateKey(std::shared_ptr<ArrayBuffer> key, std::optional<KFormatType> format,
                                                   std::optional<KeyEncoding> type,
                                                   const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) {
  if (!CheckIsInt32(key->size())) {
    throw std::runtime_error("key is too big (int32)");
  }

  if (format.has_value() && format.value() == KFormatType::PEM) {
    // For PEM, we can easily determine whether it is a public or private key
    // by looking for the respective PEM tags.
    auto res = EVPKeyPointer::TryParsePublicKeyPEM(key);
    if (res) {
      return CreateAsymmetric(KeyType::PUBLIC, std::move(res.value));
    }

    if (res.error.value() == EVPKeyPointer::PKParseError::NOT_RECOGNIZED) {
      return TryParsePrivateKey(key, format, type, passphrase);
    }
    throw std::runtime_error("Failed to read asymmetric key");
  }
}

KeyObjectData KeyObjectData::GetPrivateKey(std::shared_ptr<ArrayBuffer> key, std::optional<KFormatType> format,
                                           std::optional<KeyEncoding> type,
                                           const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase,
                                           bool isPublic) {
  throw std::runtime_error("Not yet implemented");
}

KeyObjectData TryParsePrivateKey(std::shared_ptr<ArrayBuffer> key, std::optional<KFormatType> format,
                                 std::optional<KeyEncoding> type,
                                 const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) {
  auto res = EVPKeyPointer::TryParsePrivateKey(config, buffer);
  if (res) {
    return KeyObjectData::CreateAsymmetric(KeyType::kKeyTypePrivate,
                                           std::move(res.value));
  }

  if (res.error.value() == EVPKeyPointer::PKParseError::NEED_PASSPHRASE) {
    THROW_ERR_MISSING_PASSPHRASE(env, "Passphrase required for encrypted key");
  } else {
    ThrowCryptoError(
        env, res.openssl_error.value_or(0), "Failed to read private key");
  }
  return {};
}

} // namespace margelo
