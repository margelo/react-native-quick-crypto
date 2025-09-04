#pragma once

#include <memory>
#include <optional>
#include <string>

#include "HybridKeyObjectHandleSpec.hpp"
#include "JWK.hpp"
#include "KeyDetail.hpp"
#include "KeyObjectData.hpp"
#include "KeyType.hpp"
#include "NamedCurve.hpp"

namespace margelo::nitro::crypto {

class HybridKeyObjectHandle : public HybridKeyObjectHandleSpec {
 public:
  HybridKeyObjectHandle() : HybridObject(TAG) {}

 public:
  std::shared_ptr<ArrayBuffer> exportKey(std::optional<KFormatType> format, std::optional<KeyEncoding> type,
                                         const std::optional<std::string>& cipher,
                                         const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) override;

  JWK exportJwk(const JWK& key, bool handleRsaPss) override;

  CFRGKeyPairType getAsymmetricKeyType() override;

  bool init(KeyType keyType, const std::variant<std::string, std::shared_ptr<ArrayBuffer>>& key, std::optional<KFormatType> format,
            std::optional<KeyEncoding> type, const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) override;

  std::optional<KeyType> initJwk(const JWK& keyData, std::optional<NamedCurve> namedCurve) override;

  KeyDetail keyDetail() override;

 private:
  KeyObjectData data_;

  bool initRawKey(KeyType keyType, std::shared_ptr<ArrayBuffer> keyData);
};

} // namespace margelo::nitro::crypto
