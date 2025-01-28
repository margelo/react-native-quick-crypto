#include <NitroModules/ArrayBuffer.hpp>
#include <OpenSSL/evp.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "HybridHash.hpp"

namespace margelo::nitro::crypto {

HybridHash::~HybridHash()
{
  if (ctx) {
    EVP_MD_CTX_free(ctx);
  }
}

std::shared_ptr<ArrayBuffer>
HybridHash::createHash(const std::string& algorithm)
{

  // Mock a 32 byte hash output
  uint8_t* mockHash = new uint8_t[32];
  for (int i = 0; i < 32; i++) {
    mockHash[i] = i;
  }

  return std::make_shared<NativeArrayBuffer>(
    mockHash, 32, [=]() { delete[] mockHash; });
}

void
HybridHash::update()
{
  // TODO
}

void
HybridHash::digest()
{
  // TODO
}

} // namespace margelo::nitro::crypto
