// Copyright 2022 Margelo

#ifdef ANDROID
#include "MGLHmacHostObject.h"

#include "JSIUtils/MGLTypedArray.h"
#else
#include "MGLHmacHostObject.h"
#include "MGLTypedArray.h"
#endif

#include <jsi/jsi.h>
#include <openssl/hmac.h>

#include <memory>
#include <string>
#include <vector>

#define OUT

namespace margelo {

using namespace facebook;

const EVP_MD *parseHashAlgorithm(const std::string &hashAlgorithm) {
  if (hashAlgorithm == "sha1") {
    return EVP_sha1();
  }
  if (hashAlgorithm == "sha256") {
    return EVP_sha256();
  }
  if (hashAlgorithm == "sha512") {
    return EVP_sha512();
  }
  const EVP_MD *res = EVP_get_digestbyname(hashAlgorithm.c_str());
  if (res != nullptr) {
    return res;
  }
  throw std::runtime_error("Invalid Hash Algorithm!");
}

MGLHmacHostObject::MGLHmacHostObject(
    const std::string &hashAlgorithm, jsi::Runtime &runtime,
    jsi::ArrayBuffer &key, std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue)
    : MGLSmartHostObject(jsCallInvoker, workerQueue) {
  this->context = HMAC_CTX_new();
  if (key.size(runtime) == 0) {
    HMAC_Init_ex(this->context, "", 0, parseHashAlgorithm(hashAlgorithm),
                 nullptr);
  } else {
    HMAC_Init_ex(this->context, key.data(runtime),
                 static_cast<int>(key.size(runtime)),
                 parseHashAlgorithm(hashAlgorithm), nullptr);
  }

  this->fields.push_back(HOST_LAMBDA("update", {
    if (!arguments[0].isObject() ||
        !arguments[0].getObject(runtime).isArrayBuffer(runtime)) {
      throw jsi::JSError(
          runtime,
          "MGLHmacHostObject::update: First argument ('message') "
          "has to be of type ArrayBuffer!");
    }

    auto message = arguments[0].getObject(runtime).getArrayBuffer(runtime);

    HMAC_Update(this->context, message.data(runtime), message.size(runtime));

    return jsi::Value::undefined();
  }));

  this->fields.push_back(HOST_LAMBDA("digest", {
    auto size = HMAC_size(this->context);

    unsigned char *OUT md = new unsigned char[size];
    unsigned int OUT length;

    HMAC_Final(this->context, md, &length);

    MGLTypedArray<MGLTypedArrayKind::Uint8Array> MGLtypedArray(runtime, length);
    std::vector<unsigned char> vec(md, md + length);
    MGLtypedArray.update(runtime, vec);

    return MGLtypedArray;
  }));
}

MGLHmacHostObject::~MGLHmacHostObject() {
  if (this->context != nullptr) {
    HMAC_CTX_free(this->context);
  }
}

}  // namespace margelo
