//Copyright 2022 Margelo

#include "HmacHostObject.h"

#include <jsi/jsi.h>
#include <string>
#include <openssl/hmac.h>
#include <vector>
#include "../../../../Downloads/cpp/JSI Utils/TypedArray.h"

#define OUT

namespace margelo {

using namespace facebook;

const EVP_MD* parseHashAlgorithm(const std::string& hashAlgorithm) {
  if (hashAlgorithm == "sha1") {
    return EVP_sha1();
  }
  if (hashAlgorithm == "sha256") {
    return EVP_sha256();
  }
  if (hashAlgorithm == "sha512") {
    return EVP_sha512();
  }
  throw std::runtime_error("Invalid Hash Algorithm!");
}

HmacHostObject::HmacHostObject(const std::string& hashAlgorithm,
                               const std::string& key,
                               std::shared_ptr<react::CallInvoker> jsCallInvoker,
                               std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) :
  SmartHostObject(jsCallInvoker, workerQueue) {
  this->context = HMAC_CTX_new();
  HMAC_Init_ex(this->context,
               key.data(),
               static_cast<int>(key.size()),
               parseHashAlgorithm(hashAlgorithm),
               nullptr);

  this->fields.push_back(HOST_LAMBDA("update", {
      if (!arguments[0].isString()) throw jsi::JSError(runtime, "HmacHostObject::update: First argument ('message') has to be of type string!");

      auto message = arguments[0].getString(runtime).utf8(runtime);

      const unsigned char* data = reinterpret_cast<const unsigned char*>(message.c_str());

      HMAC_Update(this->context,
                  data,
                  message.size());

      return jsi::Value::undefined();
    }));

  this->fields.push_back(HOST_LAMBDA("digest", {
      auto size = HMAC_size(this->context);

      unsigned char* OUT md = new unsigned char[size];
      unsigned int OUT length;

      HMAC_Final(this->context,
                 md,
                 &length);

      TypedArray<TypedArrayKind::Uint8Array> typedArray(runtime, length);
      std::vector<unsigned char> vec(md, md + length);
      typedArray.update(runtime, vec);

      return typedArray;
    }));
}

HmacHostObject::~HmacHostObject() {
  if (this->context != nullptr) {
    HMAC_CTX_free(this->context);
  }
}

}
