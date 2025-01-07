#include <openssl/evp.h>
#include <openssl/err.h>

#include "HybridCipherSpec.hpp"
#include "CipherArgs.hpp"

namespace margelo::nitro::crypto {

using namespace facebook;

class HybridCipher : public HybridCipherSpec {
 public:
  HybridCipher() : HybridObject(TAG) {}

 public:
  // Methods
  std::shared_ptr<ArrayBuffer>
  update(
    const std::shared_ptr<ArrayBuffer>& data
  ) override;

  std::shared_ptr<ArrayBuffer>
  final() override;

  void
  copy() override;

  inline void
  setArgs(
    const CipherArgs& args
  ) {
    this->args = args;
  };

  bool
  setAAD(
    const std::shared_ptr<ArrayBuffer>& data,
    const std::optional<double>& plaintextLength
  ) override;

  bool
  setAutoPadding(
    bool autoPad
  ) override;

  bool
  setAuthTag(
    const std::shared_ptr<ArrayBuffer>& tag
  ) override;

  std::shared_ptr<ArrayBuffer>
  getAuthTag() override;

 private:
  CipherArgs args;
};

} // namespace margelo::nitro::crypto
