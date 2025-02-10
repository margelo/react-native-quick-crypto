#include <openssl/evp.h>

#include "HybridPbkdf2Spec.hpp"
#include "fastpbkdf2.h"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridPbkdf2 : public HybridPbkdf2Spec {
 public:
  HybridPbkdf2() : HybridObject(TAG) {}

 public:
  // Methods
  std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> pbkdf2(const std::shared_ptr<ArrayBuffer>& password,
                                                                const std::shared_ptr<ArrayBuffer>& salt, double iterations, double keylen,
                                                                const std::string& digest) override;

  std::shared_ptr<ArrayBuffer> pbkdf2Sync(const std::shared_ptr<ArrayBuffer>& password, const std::shared_ptr<ArrayBuffer>& salt,
                                          double iterations, double keylen, const std::string& digest) override;
};

} // namespace margelo::nitro::crypto
