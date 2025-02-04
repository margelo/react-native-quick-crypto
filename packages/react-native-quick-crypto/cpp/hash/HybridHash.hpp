#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/evp.h>
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
  HybridHash(EVP_MD_CTX* ctx,
             const EVP_MD* md,
             const std::string& algorithm,
             const std::optional<double> outputLength)
    : HybridObject(TAG)
    , ctx(ctx)
    , md(md)
    , algorithm(algorithm)
    , outputLength(outputLength)
  {
  }
  ~HybridHash();

public:
  // Methods
  void createHash(const std::string& algorithm,
                  const std::optional<double> outputLength) override;
  void update(const std::shared_ptr<ArrayBuffer>& data) override;
  std::shared_ptr<ArrayBuffer> digest(
    const std::optional<std::string>& encoding = std::nullopt) override;
  std::shared_ptr<margelo::nitro::crypto::HybridHashSpec> copy(
    const std::optional<double> outputLength) override;
  std::vector<std::string> getSupportedHashAlgorithms() override;

private:
  // Methods
  void setParams();

private:
  // Properties
  EVP_MD_CTX* ctx = nullptr;
  const EVP_MD* md = nullptr;
  std::string algorithm = "";
  std::optional<double> outputLength = std::nullopt;
};

} // namespace margelo::nitro::crypto
