#include <NitroModules/ArrayBuffer.hpp>
#include <OpenSSL/evp.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "HybridHashSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridHash : public HybridHashSpec
{
public:
  HybridHash()
    : HybridObject(TAG)
  {
  }
  ~HybridHash();

public:
  // Methods
  void createHash(const std::string& algorithm) override;
  void update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::string digest(const std::optional<std::string>& encoding) override;

private:
  // Properties
  EVP_MD_CTX* ctx = nullptr;
  const EVP_MD* md = nullptr;
  std::string algorithm;
};

} // namespace margelo::nitro::crypto
