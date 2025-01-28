#include <NitroModules/ArrayBuffer.hpp>
#include <OpenSSL/evp.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "HybridHashSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridHash : public HybridHashSpec {
public:
  HybridHash() : HybridObject(TAG) {}
  ~HybridHash();

public:
  // Methods
  void update() override;
  void digest() override;

private:
  // Properties
  EVP_MD_CTX* ctx = nullptr;
};

} // namespace margelo::nitro::crypto
