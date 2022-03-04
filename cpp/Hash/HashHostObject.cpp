//Copyright 2022 Margelo

#include "HashHostObject.h"

#include <jsi/jsi.h>
#include <string>
#include <openssl/hmac.h>
#include <vector>
#include "../../../../Downloads/cpp/JSI Utils/TypedArray.h"

#define OUT

namespace margelo {

using namespace facebook;

const EVP_MD* parseHashAlgorithm(const std::string& hashAlgorithm) {
  EVP_MD* res = EVP_get_digestbyname(hashAlgorithm.c_str());
  if (res != nullptr) {
      return res;
  }
  throw std::runtime_error("Invalid Hash Algorithm!");
}

HashHostObject::HashHostObject(std::string hashAlgorithm,
                               unsigned int md_len,
                               std::shared_ptr<react::CallInvoker> jsCallInvoker,
                               std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue) :
  SmartHostObject(jsCallInvoker, workerQueue) {
    EVP_MD * md = parseHashAlgorithm(hashAlgorithm);
    mdctx_.reset(EVP_MD_CTX_new());
    if (!mdctx_ || EVP_DigestInit_ex(mdctx_.get(), md, nullptr) <= 0) {
        mdctx_.reset();
        return false;
    }
    md_len_ = EVP_MD_size(md);
    if (md_len != -1) {
        md_len_ = md_len;
    }

  this->fields.push_back(HOST_LAMBDA("update", {
      if (!arguments[0].isString()) throw jsi::JSError(runtime, "HmacHostObject::update: First argument ('message') has to be of type string!");

      auto messageBuffer = arguments[0].getObject(runtime).getArrayBuffer(runtime);

      const unsigned char* data = reinterpret_cast<const unsigned char*>(messageBuffer.data(runtime));
      int size = arguments[1].asNumber();

      EVP_DigestUpdate(mdctx_.get(), data, len);

      return jsi::Value::undefined();
    }));

  this->fields.push_back(HOST_LAMBDA("digest", {
      unsigned int len = md_len_;
      auto size = HMAC_size(this->context);

      if (digest_ == nullptr && len > 0) {
          // Some hash algorithms such as SHA3 do not support calling
          // EVP_DigestFinal_ex more than once, however, Hash._flush
          // and Hash.digest can both be used to retrieve the digest,
          // so we need to cache it.
          // See https://github.com/nodejs/node/issues/28245.

          char* md_value = MallocOpenSSL<char>(len);

          size_t default_len = EVP_MD_CTX_size(hash->mdctx_.get());
          int ret;
          if (len == default_len) {
              ret = EVP_DigestFinal_ex(
                      mdctx_.get(),
                      reinterpret_cast<unsigned char*>(md_value),
                      &len);
          } else {
              ret = EVP_DigestFinalXOF(
                      mdctx_.get(),
                      reinterpret_cast<unsigned char*>(md_value),
                      len);
          }

          if (ret != 1) {
              throw jsi::Error(runtime, ERR_get_error());
          }

          digest_ = md_value;
      }

      TypedArray<TypedArrayKind::Uint8Array> typedArray(runtime, length);
      std::vector<unsigned char> vec(_digest, _digest + len);
      typedArray.update(runtime, vec);
      return typedArray;
    }));
}

HashHostObject::~HashHostObject() {
  if (this->mdctx_ != nullptr) {
      EVP_MD_CTX_free(this->mdctx_);
  }
  if (_digest != nullptr) {
      delete [] _digest;
  }
}

}
