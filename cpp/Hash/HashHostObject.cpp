//Copyright 2022 Margelo

#include "HashHostObject.h"

#include <jsi/jsi.h>
#include <string>
#include <vector>
#include "../../../../Downloads/cpp/JSI Utils/TypedArray.h"
#include <openssl/err.h>


#define OUT

namespace margelo {

using namespace facebook;
namespace jsi = facebook::jsi;

const EVP_MD* parseHashAlgorithmForHashObject(const std::string& hashAlgorithm) {
  const EVP_MD* res = EVP_get_digestbyname(hashAlgorithm.c_str());
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
    const EVP_MD * md = parseHashAlgorithmForHashObject(hashAlgorithm);
    mdctx_ = EVP_MD_CTX_new();
    if (!mdctx_ || EVP_DigestInit_ex(mdctx_, md, nullptr) <= 0) {
        EVP_MD_CTX_reset(mdctx_);
        return;
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

      EVP_DigestUpdate(mdctx_, data, size);

      return jsi::Value::undefined();
    }));

  this->fields.push_back(HOST_LAMBDA("digest", {
      unsigned int len = md_len_;

      if (digest_ == nullptr && len > 0) {
          // Some hash algorithms such as SHA3 do not support calling
          // EVP_DigestFinal_ex more than once, however, Hash._flush
          // and Hash.digest can both be used to retrieve the digest,
          // so we need to cache it.
          // See https://github.com/nodejs/node/issues/28245.

          char* md_value = new char[len];

          size_t default_len = EVP_MD_CTX_size(mdctx_);
          int ret;
          if (len == default_len) {
              ret = EVP_DigestFinal_ex(
                      mdctx_,
                      reinterpret_cast<unsigned char*>(md_value),
                      &len);
          } else {
              ret = EVP_DigestFinalXOF(
                      mdctx_,
                      reinterpret_cast<unsigned char*>(md_value),
                      len);
          }

          if (ret != 1) {
              throw jsi::JSError(runtime, "openSSL error:" + ERR_get_error());
          }

          digest_ = md_value;
      }

      TypedArray<TypedArrayKind::Uint8Array> typedArray(runtime, len);
      std::vector<unsigned char> vec(digest_, digest_ + len);
      typedArray.update(runtime, vec);
      return typedArray;
    }));
}

HashHostObject::~HashHostObject() {
  if (this->mdctx_ != nullptr) {
      EVP_MD_CTX_free(this->mdctx_);
  }
  if (digest_ != nullptr) {
      delete [] digest_;
  }
}

}
