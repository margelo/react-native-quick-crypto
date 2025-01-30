#include <NitroModules/ArrayBuffer.hpp>
#include <openssl/evp.h>
#include <memory>
#include <optional>
#include <string>

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
  std::shared_ptr<ArrayBuffer> digest(
    const std::optional<std::string>& encoding = std::nullopt) override;

private:
  // Properties
  EVP_MD_CTX* ctx = nullptr;
  const EVP_MD* md = nullptr;
  std::string algorithm;
};

} // namespace margelo::nitro::crypto
