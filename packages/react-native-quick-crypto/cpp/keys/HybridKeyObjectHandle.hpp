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
  HybridKeyObjectHandle();

 public:
  std::shared_ptr<ArrayBuffer> exportKey(std::optional<KFormatType> format, std::optional<KeyEncoding> type,
                                         const std::optional<std::string>& cipher,
                                         const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) override;

  JWK exportJwk(const JWK& key, bool handleRsaPss) override;

  std::shared_ptr<ArrayBuffer> exportRawPublic() override;

  std::shared_ptr<ArrayBuffer> exportRawPrivate() override;

  std::shared_ptr<ArrayBuffer> exportRawSeed() override;

  std::shared_ptr<ArrayBuffer> exportECPublicRaw(bool compressed) override;

  std::shared_ptr<ArrayBuffer> exportECPrivateRaw() override;

  AsymmetricKeyType getAsymmetricKeyType() override;

  bool init(KeyType keyType, const std::variant<std::shared_ptr<ArrayBuffer>, std::string>& key, std::optional<KFormatType> format,
            std::optional<KeyEncoding> type, const std::optional<std::shared_ptr<ArrayBuffer>>& passphrase) override;

  bool initECRaw(const std::string& namedCurve, const std::shared_ptr<ArrayBuffer>& keyData) override;

  bool initPqcRaw(const std::string& algorithmName, const std::shared_ptr<ArrayBuffer>& keyData, bool isPublic) override;

  bool initRawPublic(const std::string& asymmetricKeyType, const std::shared_ptr<ArrayBuffer>& keyData,
                     const std::optional<std::string>& namedCurve) override;

  bool initRawPrivate(const std::string& asymmetricKeyType, const std::shared_ptr<ArrayBuffer>& keyData,
                      const std::optional<std::string>& namedCurve) override;

  bool initRawSeed(const std::string& asymmetricKeyType, const std::shared_ptr<ArrayBuffer>& keyData) override;

  std::optional<KeyType> initJwk(const JWK& keyData, std::optional<NamedCurve> namedCurve) override;

  KeyDetail keyDetail() override;

  bool keyEquals(const std::shared_ptr<HybridKeyObjectHandleSpec>& other) override;

  double getSymmetricKeySize() override;

  bool checkEcKeyData() override;

  const KeyObjectData& getKeyObjectData() const {
    return data_;
  }

  void setKeyObjectData(KeyObjectData data) {
    data_ = std::move(data);
  }

 private:
  KeyObjectData data_;

  bool initRawKey(KeyType keyType, std::shared_ptr<ArrayBuffer> keyData);
};

} // namespace margelo::nitro::crypto
