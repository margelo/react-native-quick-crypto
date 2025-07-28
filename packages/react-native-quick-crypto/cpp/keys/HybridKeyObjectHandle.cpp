#include <stdexcept>

#include "HybridKeyObjectHandle.hpp"
#include "Utils.hpp"

namespace margelo::nitro::crypto {

std::shared_ptr<ArrayBuffer> HybridKeyObjectHandle::exportKey(std::optional<KFormatType> format, std::optional<KeyEncoding> type,
                                                              const std::optional<std::string>& cipher,
                                                              const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) {
  throw std::runtime_error("Not yet implemented");
}

JWK HybridKeyObjectHandle::exportJwk(const JWK& key, bool handleRsaPss) {
  throw std::runtime_error("Not yet implemented");
}

CFRGKeyPairType HybridKeyObjectHandle::getAsymmetricKeyType() {
  throw std::runtime_error("Not yet implemented");
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

} // namespace margelo::nitro::crypto
