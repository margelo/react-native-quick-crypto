#pragma once

#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

class OCBCipher : public HybridCipher {
 public:
  OCBCipher() : HybridObject(TAG) {}
  void init(const std::shared_ptr<ArrayBuffer>& key, const std::shared_ptr<ArrayBuffer>& iv, size_t tag_len = 16);

  std::shared_ptr<ArrayBuffer> getAuthTag() override;
  bool setAuthTag(const std::shared_ptr<ArrayBuffer>& tag) override;

 protected:
  size_t auth_tag_len = 16;
};

} // namespace margelo::nitro::crypto
