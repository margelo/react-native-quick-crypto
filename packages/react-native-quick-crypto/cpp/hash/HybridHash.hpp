#include "HashContext.hpp"
#include <NitroModules/ArrayBuffer.hpp>
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
  HybridHash(::margelo::quickcrypto::DigestContext context, std::optional<double> outputLength)
      : HybridObject(TAG), ctx(std::move(context)), outputLength(outputLength) {}

 public:
  // Methods
  void createHash(const std::string& algorithm, const std::optional<double> outputLength) override;
  void update(const std::variant<std::shared_ptr<ArrayBuffer>, std::string>& data) override;
  std::shared_ptr<ArrayBuffer> digest(const std::optional<std::string>& encoding = std::nullopt) override;
  std::shared_ptr<margelo::nitro::crypto::HybridHashSpec> copy(const std::optional<double> outputLength) override;
  std::vector<std::string> getSupportedHashAlgorithms() override;
  std::string getOpenSSLVersion() override;

 private:
  // Methods
  void setParams();

 private:
  // Properties
  ::margelo::quickcrypto::DigestContext ctx{nullptr, EVP_MD_CTX_free};
  std::optional<double> outputLength = std::nullopt;
};

} // namespace margelo::nitro::crypto
