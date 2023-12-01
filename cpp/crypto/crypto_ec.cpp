//
//  crypto_ec.cpp
//  BEMCheckBox
//
//  Created by Oscar Franco on 30/11/23.
//

#include "crypto_ec.h"

namespace margelo {
namespace jsi = facebook::jsi;

ECPointPointer ECDH::BufferToPoint(jsi::Runtime &rt,
                                   const EC_GROUP* group,
                                   jsi::ArrayBuffer &buf) {
  int r;

  ECPointPointer pub(EC_POINT_new(group));
  if (!pub) {
    throw std::runtime_error("Failed to allocate EC_POINT for a public key");
    return pub;
  }

//    TODO re-insert this check
//  if (UNLIKELY(!input.CheckSizeInt32())) {
//    THROW_ERR_OUT_OF_RANGE(env, "buffer is too big");
//    return ECPointPointer();
//  }
  r = EC_POINT_oct2point(
      group,
      pub.get(),
      buf.data(rt),
      buf.size(rt),
      nullptr);

  if (!r)
    return ECPointPointer();

  return pub;
}

}
