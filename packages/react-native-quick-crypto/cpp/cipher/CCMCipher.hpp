#pragma once

#include "HybridCipher.hpp"

namespace margelo::nitro::crypto {

class CCMCipher : public HybridCipher {
 public:

 private:
  static constexpr int kMaxMessageSize = ((1ull << 32) - 1) * 8;
};

}  // namespace margelo::nitro::crypto
