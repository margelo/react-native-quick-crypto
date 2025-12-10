#pragma once

#include "HybridRsaCipherSpec.hpp"
#include <memory>

namespace margelo::nitro::crypto {

class HybridRsaCipher : public HybridRsaCipherSpec {
 public:
  HybridRsaCipher() : HybridObject(TAG) {}

  std::shared_ptr<ArrayBuffer> encrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                       const std::shared_ptr<ArrayBuffer>& data, double padding, const std::string& hashAlgorithm,
                                       const std::optional<std::shared_ptr<ArrayBuffer>>& label) override;

  std::shared_ptr<ArrayBuffer> decrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                       const std::shared_ptr<ArrayBuffer>& data, double padding, const std::string& hashAlgorithm,
                                       const std::optional<std::shared_ptr<ArrayBuffer>>& label) override;

  std::shared_ptr<ArrayBuffer> publicDecrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                             const std::shared_ptr<ArrayBuffer>& data, double padding) override;

  std::shared_ptr<ArrayBuffer> privateEncrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                              const std::shared_ptr<ArrayBuffer>& data, double padding) override;

  std::shared_ptr<ArrayBuffer> privateDecrypt(const std::shared_ptr<HybridKeyObjectHandleSpec>& keyHandle,
                                              const std::shared_ptr<ArrayBuffer>& data, double padding, const std::string& hashAlgorithm,
                                              const std::optional<std::shared_ptr<ArrayBuffer>>& label) override;

  void loadHybridMethods() override;
};

} // namespace margelo::nitro::crypto
