//
//  crypto_ec.cpp
//  BEMCheckBox
//
//  Created by Oscar Franco on 30/11/23.
//

#include "crypto_ec.hpp"

namespace margelo {
namespace jsi = facebook::jsi;

ECPointPointer ECDH::BufferToPoint(
                                   const EC_GROUP* group,
                                   jsi::ArrayBuffer buf) {
  int r;

  ECPointPointer pub(EC_POINT_new(group));
  if (!pub) {
    THROW_ERR_CRYPTO_OPERATION_FAILED(env,
        "Failed to allocate EC_POINT for a public key");
    return pub;
  }

  ArrayBufferOrViewContents<unsigned char> input(buf);
  if (UNLIKELY(!input.CheckSizeInt32())) {
    THROW_ERR_OUT_OF_RANGE(env, "buffer is too big");
    return ECPointPointer();
  }
  r = EC_POINT_oct2point(
      group,
      pub.get(),
      input.data(),
      input.size(),
      nullptr);
  if (!r)
    return ECPointPointer();

  return pub;
}

}
