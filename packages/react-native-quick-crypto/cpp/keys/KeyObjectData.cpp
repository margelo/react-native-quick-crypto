#include "KeyObjectData.hpp"
#include "Utils.hpp"
#include <optional>

namespace margelo::nitro::crypto {

ncrypto::EVPKeyPointer::PrivateKeyEncodingConfig GetPrivateKeyEncodingConfig(KFormatType format, KeyEncoding type) {
  auto pk_format = static_cast<ncrypto::EVPKeyPointer::PKFormatType>(format);
  auto pk_type = static_cast<ncrypto::EVPKeyPointer::PKEncodingType>(type);

  auto config = ncrypto::EVPKeyPointer::PrivateKeyEncodingConfig(false, pk_format, pk_type);
  return config;
}

ncrypto::EVPKeyPointer::PublicKeyEncodingConfig GetPublicKeyEncodingConfig(KFormatType format, KeyEncoding type) {
  auto pk_format = static_cast<ncrypto::EVPKeyPointer::PKFormatType>(format);
  auto pk_type = static_cast<ncrypto::EVPKeyPointer::PKEncodingType>(type);

  auto config = ncrypto::EVPKeyPointer::PublicKeyEncodingConfig(false, pk_format, pk_type);
  return config;
}

KeyObjectData TryParsePrivateKey(std::shared_ptr<ArrayBuffer> key, std::optional<KFormatType> format, std::optional<KeyEncoding> type,
                                 const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) {
  auto config = GetPrivateKeyEncodingConfig(format.value(), type.value());
  auto buffer = ncrypto::Buffer<const unsigned char>{key->data(), key->size()};
  auto res = ncrypto::EVPKeyPointer::TryParsePrivateKey(config, buffer);
  if (res) {
    return KeyObjectData::CreateAsymmetric(KeyType::PRIVATE, std::move(res.value));
  }

  if (res.error.value() == ncrypto::EVPKeyPointer::PKParseError::NEED_PASSPHRASE) {
    throw std::runtime_error("Passphrase required for encrypted key");
  } else {
    throw std::runtime_error("Failed to read private key");
  }
}

KeyObjectData::KeyObjectData(std::nullptr_t) : key_type_(KeyType::SECRET) {}

KeyObjectData::KeyObjectData(std::shared_ptr<ArrayBuffer> symmetric_key)
    : key_type_(KeyType::SECRET), data_(std::make_shared<Data>(std::move(symmetric_key))) {}

KeyObjectData::KeyObjectData(KeyType type, ncrypto::EVPKeyPointer&& pkey)
    : key_type_(type), data_(std::make_shared<Data>(std::move(pkey))) {}

KeyObjectData KeyObjectData::CreateSecret(std::shared_ptr<ArrayBuffer> key) {
  return KeyObjectData(std::move(key));
}

KeyObjectData KeyObjectData::CreateAsymmetric(KeyType key_type, ncrypto::EVPKeyPointer&& pkey) {
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
  // Check if key size fits in int32_t without using double conversion
  if (key->size() > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
    std::string error_msg = "key is too big (int32): size=" + std::to_string(key->size()) +
                            ", max_int32=" + std::to_string(std::numeric_limits<int32_t>::max());
    throw std::runtime_error(error_msg);
  }

  if (format.has_value() && (format.value() == KFormatType::PEM || format.value() == KFormatType::DER)) {
    auto buffer = ncrypto::Buffer<const unsigned char>{key->data(), key->size()};

    if (format.value() == KFormatType::PEM) {
      // For PEM, we can easily determine whether it is a public or private key
      // by looking for the respective PEM tags.
      auto res = ncrypto::EVPKeyPointer::TryParsePublicKeyPEM(buffer);
      if (res) {
        return CreateAsymmetric(KeyType::PUBLIC, std::move(res.value));
      }

      if (res.error.has_value() && res.error.value() == ncrypto::EVPKeyPointer::PKParseError::NOT_RECOGNIZED) {
        auto config = GetPrivateKeyEncodingConfig(format.value(), type.value());
        if (passphrase.has_value()) {
          auto& passphrase_ptr = passphrase.value();
          config.passphrase = std::make_optional(ncrypto::DataPointer(passphrase_ptr->data(), passphrase_ptr->size()));
        }

        auto private_res = ncrypto::EVPKeyPointer::TryParsePrivateKey(config, buffer);
        if (private_res) {
          return CreateAsymmetric(KeyType::PRIVATE, std::move(private_res.value));
        }
      }
      throw std::runtime_error("Failed to read PEM asymmetric key");
    } else if (format.value() == KFormatType::DER) {
      // For DER, try parsing as public key first
      if (type.has_value() && type.value() == KeyEncoding::SPKI) {
        auto public_config = GetPublicKeyEncodingConfig(format.value(), type.value());
        auto res = ncrypto::EVPKeyPointer::TryParsePublicKey(public_config, buffer);
        if (res) {
          return CreateAsymmetric(KeyType::PUBLIC, std::move(res.value));
        }
      } else if (type.has_value() && type.value() == KeyEncoding::PKCS8) {
        auto private_config = GetPrivateKeyEncodingConfig(format.value(), type.value());
        if (passphrase.has_value()) {
          auto& passphrase_ptr = passphrase.value();
          private_config.passphrase = std::make_optional(ncrypto::DataPointer(passphrase_ptr->data(), passphrase_ptr->size()));
        }
        auto res = ncrypto::EVPKeyPointer::TryParsePrivateKey(private_config, buffer);
        if (res) {
          return CreateAsymmetric(KeyType::PRIVATE, std::move(res.value));
        }
      }
      throw std::runtime_error("Failed to read DER asymmetric key");
    }
  }

  throw std::runtime_error("Unsupported key format for GetPublicOrPrivateKey. Only PEM and DER are supported.");
}

KeyObjectData KeyObjectData::GetPrivateKey(std::shared_ptr<ArrayBuffer> key, std::optional<KFormatType> format,
                                           std::optional<KeyEncoding> type, const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase,
                                           bool isPublic) {
  // Check if key size fits in int32_t without using double conversion
  if (key->size() > static_cast<size_t>(std::numeric_limits<int32_t>::max())) {
    std::string error_msg = "key is too big (int32): size=" + std::to_string(key->size()) +
                            ", max_int32=" + std::to_string(std::numeric_limits<int32_t>::max());
    throw std::runtime_error(error_msg);
  }

  if (format.has_value() && (format.value() == KFormatType::PEM || format.value() == KFormatType::DER)) {
    auto buffer = ncrypto::Buffer<const unsigned char>{key->data(), key->size()};

    if (format.value() == KFormatType::PEM) {
      return TryParsePrivateKey(key, format, type, passphrase);
    } else if (format.value() == KFormatType::DER) {
      // For DER private keys, use PKCS8 encoding
      if (type.has_value() && type.value() == KeyEncoding::PKCS8) {
        auto private_config = GetPrivateKeyEncodingConfig(format.value(), type.value());
        if (passphrase.has_value()) {
          auto& passphrase_ptr = passphrase.value();
          private_config.passphrase = std::make_optional(ncrypto::DataPointer(passphrase_ptr->data(), passphrase_ptr->size()));
        }
        auto res = ncrypto::EVPKeyPointer::TryParsePrivateKey(private_config, buffer);
        if (res) {
          return CreateAsymmetric(KeyType::PRIVATE, std::move(res.value));
        }
      }
      throw std::runtime_error("Failed to read DER private key");
    }
  }

  throw std::runtime_error("Unsupported key format for GetPrivateKey. Only PEM and DER are supported.");
}

} // namespace margelo::nitro::crypto
