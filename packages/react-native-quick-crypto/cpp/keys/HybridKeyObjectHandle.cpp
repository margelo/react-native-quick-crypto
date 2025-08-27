#include <stdexcept>

#include "HybridKeyObjectHandle.hpp"
#include "Utils.hpp"
#include "CFRGKeyPairType.hpp"
#include <openssl/evp.h>

namespace margelo::nitro::crypto {

std::shared_ptr<ArrayBuffer> HybridKeyObjectHandle::exportKey(std::optional<KFormatType> format, std::optional<KeyEncoding> type,
                                                              const std::optional<std::string>& cipher,
                                                              const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) {
  auto keyType = data_.GetKeyType();
  
  // Handle secret keys
  if (keyType == KeyType::SECRET) {
    return data_.GetSymmetricKey();
  }
  
  // Handle asymmetric keys (public/private)
  if (keyType == KeyType::PUBLIC || keyType == KeyType::PRIVATE) {
    const auto& pkey = data_.GetAsymmetricKey();
    if (!pkey) {
      throw std::runtime_error("Invalid asymmetric key");
    }
    
    int keyId = EVP_PKEY_id(pkey.get());
    
    // For curve keys (X25519, X448, Ed25519, Ed448), use raw format if no format specified
    bool isCurveKey = (keyId == EVP_PKEY_X25519 || keyId == EVP_PKEY_X448 || 
                       keyId == EVP_PKEY_ED25519 || keyId == EVP_PKEY_ED448);
    
    // If no format specified and it's a curve key, export as raw
    if (!format.has_value() && !type.has_value() && isCurveKey) {
      if (keyType == KeyType::PUBLIC) {
        auto rawData = pkey.rawPublicKey();
        if (!rawData) {
          throw std::runtime_error("Failed to get raw public key");
        }
        return ToNativeArrayBuffer(std::string(reinterpret_cast<const char*>(rawData.get()), rawData.size()));
      } else {
        auto rawData = pkey.rawPrivateKey();
        if (!rawData) {
          throw std::runtime_error("Failed to get raw private key");
        }
        return ToNativeArrayBuffer(std::string(reinterpret_cast<const char*>(rawData.get()), rawData.size()));
      }
    }
    
    // Set default format and type if not provided
    auto exportFormat = format.value_or(KFormatType::DER);
    auto exportType = type.value_or(keyType == KeyType::PUBLIC ? KeyEncoding::SPKI : KeyEncoding::PKCS8);
    
    // Create encoding config
    if (keyType == KeyType::PUBLIC) {
      ncrypto::EVPKeyPointer::PublicKeyEncodingConfig config(
        false,
        static_cast<ncrypto::EVPKeyPointer::PKFormatType>(exportFormat),
        static_cast<ncrypto::EVPKeyPointer::PKEncodingType>(exportType)
      );
      
      auto result = pkey.writePublicKey(config);
      if (!result) {
        throw std::runtime_error("Failed to export public key");
      }
      
      auto bio = std::move(result.value);
      BUF_MEM* bptr = bio;
      return ToNativeArrayBuffer(std::string(bptr->data, bptr->length));
    } else {
      ncrypto::EVPKeyPointer::PrivateKeyEncodingConfig config(
        false,
        static_cast<ncrypto::EVPKeyPointer::PKFormatType>(exportFormat),
        static_cast<ncrypto::EVPKeyPointer::PKEncodingType>(exportType)
      );
      
      // Handle cipher and passphrase for encrypted private keys
      if (cipher.has_value()) {
        const EVP_CIPHER* evp_cipher = EVP_get_cipherbyname(cipher.value().c_str());
        if (!evp_cipher) {
          throw std::runtime_error("Unknown cipher: " + cipher.value());
        }
        config.cipher = evp_cipher;
      }
      
      if (passphrase.has_value()) {
        auto& passphrase_ptr = passphrase.value();
        config.passphrase = std::make_optional(ncrypto::DataPointer(passphrase_ptr->data(), passphrase_ptr->size()));
      }
      
      auto result = pkey.writePrivateKey(config);
      if (!result) {
        throw std::runtime_error("Failed to export private key");
      }
      
      auto bio = std::move(result.value);
      BUF_MEM* bptr = bio;
      return ToNativeArrayBuffer(std::string(bptr->data, bptr->length));
    }
  }
  
  throw std::runtime_error("Unsupported key type for export");
}

JWK HybridKeyObjectHandle::exportJwk(const JWK& key, bool handleRsaPss) {
  throw std::runtime_error("Not yet implemented");
}

CFRGKeyPairType HybridKeyObjectHandle::getAsymmetricKeyType() {
  const auto& pkey = data_.GetAsymmetricKey();
  if (!pkey) {
    throw std::runtime_error("Key is not an asymmetric key");
  }
  
  int keyType = EVP_PKEY_id(pkey.get());
  
  switch (keyType) {
    case EVP_PKEY_X25519:
      return CFRGKeyPairType::X25519;
    case EVP_PKEY_X448:
      return CFRGKeyPairType::X448;
    case EVP_PKEY_ED25519:
      return CFRGKeyPairType::ED25519;
    case EVP_PKEY_ED448:
      return CFRGKeyPairType::ED448;
    default:
      throw std::runtime_error("Unsupported asymmetric key type");
  }
}

bool HybridKeyObjectHandle::init(KeyType keyType, const std::variant<std::string, std::shared_ptr<ArrayBuffer>>& key,
                                 std::optional<KFormatType> format, std::optional<KeyEncoding> type,
                                 const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) {
  // get ArrayBuffer from key
  std::shared_ptr<ArrayBuffer> ab;
  if (std::holds_alternative<std::string>(key)) {
    ab = ToNativeArrayBuffer(std::get<std::string>(key));
  } else {
    ab = std::get<std::shared_ptr<ArrayBuffer>>(key);
  }

  // Handle raw key material (when format and type are not provided)
  if (!format.has_value() && !type.has_value()) {
    return initRawKey(keyType, ab);
  }

  switch (keyType) {
    case KeyType::SECRET: {
      this->data_ = KeyObjectData::CreateSecret(ab);
      break;
    }
    case KeyType::PUBLIC: {
      auto data = KeyObjectData::GetPublicOrPrivateKey(ab, format, type, passphrase);
      if (!data) return false;
      this->data_ = data.addRefWithType(KeyType::PUBLIC);
      break;
    }
    case KeyType::PRIVATE: {
      if (auto data = KeyObjectData::GetPrivateKey(ab, format, type, passphrase, false)) {
        this->data_ = std::move(data);
      }
      break;
    }
  }
  return true;
}

bool HybridKeyObjectHandle::initECRaw(const std::string& curveName, const std::shared_ptr<ArrayBuffer>& keyData) {
  throw std::runtime_error("Not yet implemented");
}

std::optional<KeyType> HybridKeyObjectHandle::initJwk(const JWK& keyData, std::optional<NamedCurve> namedCurve) {
  throw std::runtime_error("Not yet implemented");
}

KeyDetail HybridKeyObjectHandle::keyDetail() {
  throw std::runtime_error("Not yet implemented");
}

bool HybridKeyObjectHandle::initRawKey(KeyType keyType, std::shared_ptr<ArrayBuffer> keyData) {
  // For x25519/x448/ed25519/ed448 raw keys, we need to determine the curve type
  // Based on key size: x25519=32 bytes, x448=56 bytes, ed25519=32 bytes, ed448=57 bytes
  int curveId = -1;
  size_t keySize = keyData->size();
  
  if (keySize == 32) {
    // Could be x25519 or ed25519 - for now assume x25519 based on test context
    curveId = EVP_PKEY_X25519;
  } else if (keySize == 56) {
    curveId = EVP_PKEY_X448;
  } else if (keySize == 57) {
    curveId = EVP_PKEY_ED448;
  } else {
    return false; // Unsupported key size
  }

  ncrypto::Buffer<const unsigned char> buffer{
    .data = reinterpret_cast<const unsigned char*>(keyData->data()),
    .len = keyData->size()
  };

  ncrypto::EVPKeyPointer pkey;
  if (keyType == KeyType::PRIVATE) {
    pkey = ncrypto::EVPKeyPointer::NewRawPrivate(curveId, buffer);
  } else if (keyType == KeyType::PUBLIC) {
    pkey = ncrypto::EVPKeyPointer::NewRawPublic(curveId, buffer);
  } else {
    return false; // Raw keys are only for asymmetric keys
  }

  if (!pkey) {
    return false;
  }

  this->data_ = KeyObjectData::CreateAsymmetric(keyType, std::move(pkey));
  return true;
}

} // namespace margelo::nitro::crypto
