#include <NitroModules/ArrayBuffer.hpp>
#include <memory>
#include <openssl/evp.h>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "HybridHmacSpec.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridHmac : public HybridHmacSpec {
 public:
  HybridHmac() : HybridObject(TAG) {}
  ~HybridHmac();

 public:
  // Methods
  void createHmac(const std::string& algorithm, const std::shared_ptr<ArrayBuffer>& key) override;
  void update(const std::variant<std::string, std::shared_ptr<ArrayBuffer>>& data) override;
  std::shared_ptr<ArrayBuffer> digest() override;

 private:
  // Properties
  EVP_MAC_CTX* ctx = nullptr;
  std::string algorithm = "";
};

} // namespace margelo::nitro::crypto
