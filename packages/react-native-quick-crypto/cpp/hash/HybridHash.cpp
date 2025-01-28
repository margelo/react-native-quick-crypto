#include <memory>
#include <NitroModules/ArrayBuffer.hpp>
#include <OpenSSL/evp.h>
#include <optional>
#include <string>
#include <vector>

#include "HybridHash.hpp"

namespace margelo::nitro::crypto {

HybridHash::~HybridHash() {
  if (ctx) {
    EVP_MD_CTX_free(ctx);
  }
}

void
HybridHash::update() {
  //  TODO
}

void
HybridHash::digest() {
  // TODO
}

} // namespace margelo::nitro::crypto
