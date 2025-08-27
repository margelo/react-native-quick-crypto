#include "KeyObjectData.hpp"
#include "Utils.hpp"
#include <optional>

namespace margelo {

using namespace margelo::nitro::crypto;

ncrypto::EVPKeyPointer::PrivateKeyEncodingConfig GetPrivateKeyEncodingConfig(
  KFormatType format,
  KeyEncoding type) {
auto pk_format = static_cast<ncrypto::EVPKeyPointer::PKFormatType>(format);
auto pk_type = static_cast<ncrypto::EVPKeyPointer::PKEncodingType>(type);

auto config = ncrypto::EVPKeyPointer::PrivateKeyEncodingConfig(false, pk_format, pk_type);
return config;
}

KeyObjectData TryParsePrivateKey(std::shared_ptr<ArrayBuffer> key, std::optional<KFormatType> format,
  std::optional<KeyEncoding> type,
  const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) {
  auto config = GetPrivateKeyEncodingConfig(format.value(), type.value());
  auto buffer = ncrypto::Buffer<const unsigned char>{key->data(), key->size()};
  auto res = ncrypto::EVPKeyPointer::TryParsePrivateKey(config, buffer);
  if (res) {
    return KeyObjectData::CreateAsymmetric(KeyType::PRIVATE,
            std::move(res.value));
  }

  if (res.error.value() == ncrypto::EVPKeyPointer::PKParseError::NEED_PASSPHRASE) {
    throw std::runtime_error("Passphrase required for encrypted key");
  } else {
    throw std::runtime_error("Failed to read private key");
  }
}

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
  if (!data_) {
    throw std::runtime_error("Invalid key object: no key data available");
  }
  return key_type_;
}

const ncrypto::EVPKeyPointer& KeyObjectData::GetAsymmetricKey() const {
  if (key_type_ == KeyType::SECRET) {
    throw std::runtime_error("Cannot get asymmetric key from secret key object");
  }
  if (!data_) {
    throw std::runtime_error("Invalid key object: no key data available");
  }
  return data_->asymmetric_key;
}

std::shared_ptr<ArrayBuffer> KeyObjectData::GetSymmetricKey() const {
  if (key_type_ != KeyType::SECRET) {
    throw std::runtime_error("Cannot get symmetric key from asymmetric key object");
  }
  if (!data_) {
    throw std::runtime_error("Invalid key object: no key data available");
  }
  return data_->symmetric_key;
}

size_t KeyObjectData::GetSymmetricKeySize() const {
  if (key_type_ != KeyType::SECRET) {
    throw std::runtime_error("Cannot get symmetric key size from asymmetric key object");
  }
  if (!data_) {
    throw std::runtime_error("Invalid key object: no key data available");
  }
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
    auto config = GetPrivateKeyEncodingConfig(format.value(), type.value());
    auto buffer = ncrypto::Buffer<const unsigned char>{key->data(), key->size()};
    auto res = ncrypto::EVPKeyPointer::TryParsePublicKeyPEM(buffer);
    if (res) {
      return CreateAsymmetric(KeyType::PUBLIC, std::move(res.value));
    }

    if (res.error.has_value() && res.error.value() == ncrypto::EVPKeyPointer::PKParseError::NOT_RECOGNIZED) {
      if (passphrase.has_value()) {
        auto& passphrase_ptr = passphrase.value();
        config.passphrase = std::make_optional(ncrypto::DataPointer(passphrase_ptr->data(), passphrase_ptr->size()));
      }

      auto private_res = ncrypto::EVPKeyPointer::TryParsePrivateKey(config, buffer);
      if (private_res) {
        return CreateAsymmetric(KeyType::PRIVATE, std::move(private_res.value));
      }
      // TODO: Handle private key parsing errors
    }
    throw std::runtime_error("Failed to read asymmetric key");
  }

  throw std::runtime_error("Unsupported key format for GetPublicOrPrivateKey. Only PEM is supported.");
}

KeyObjectData KeyObjectData::GetPrivateKey(std::shared_ptr<ArrayBuffer> key, std::optional<KFormatType> format,
                                           std::optional<KeyEncoding> type,
                                           const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase,
                                           bool isPublic) {
  // TODO: Node's KeyObjectData::GetPrivateKeyFromJs checks for key "IsString" or "IsAnyBufferSource"
  //       We have converted key to an ArrayBuffer - not sure if that's correct
  return TryParsePrivateKey(key, format, type, passphrase);
}

} // namespace margelo
