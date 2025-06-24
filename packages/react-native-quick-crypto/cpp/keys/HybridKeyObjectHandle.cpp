#include "HybridKeyObjectHandle.hpp"

#include <stdexcept>

namespace margelo::nitro::crypto {

std::shared_ptr<ArrayBuffer> HybridKeyObjectHandle::exportKey(
    std::optional<KFormatType> format,
    std::optional<KeyEncoding> type,
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

bool HybridKeyObjectHandle::init(
    KeyType keyType,
    const std::variant<std::string, std::shared_ptr<ArrayBuffer>>& key,
    std::optional<KFormatType> format,
    std::optional<KeyEncoding> type,
    const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) {
  throw std::runtime_error("Not yet implemented");
}

bool HybridKeyObjectHandle::initECRaw(
    const std::string& curveName,
    const std::shared_ptr<ArrayBuffer>& keyData) {
  throw std::runtime_error("Not yet implemented");
}

std::optional<KeyType> HybridKeyObjectHandle::initJwk(
    const JWK& keyData,
    std::optional<NamedCurve> namedCurve) {
  throw std::runtime_error("Not yet implemented");
}

KeyDetail HybridKeyObjectHandle::keyDetail() {
  throw std::runtime_error("Not yet implemented");
}

} // namespace margelo::nitro::crypto
