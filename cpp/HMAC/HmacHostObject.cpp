//
//  HmacHostObject.cpp
//  PinkPanda
//
//  Created by Marc Rousavy on 22.02.22.
//

#include "HmacHostObject.h"

#include <jsi/jsi.h>
#include <string>
#include <openssl/hmac.h>
#include <vector>
#include "../../../../Downloads/cpp/JSI Utils/TypedArray.h"

#define OUT

namespace fastHMAC {

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

HmacHostObject::HmacHostObject(const std::string& hashAlgorithm, const std::string& key) {
  this->context = HMAC_CTX_new();
  HMAC_Init_ex(this->context,
               key.data(),
               static_cast<int>(key.size()),
               parseHashAlgorithm(hashAlgorithm),
               nullptr);
}

HmacHostObject::~HmacHostObject() {
  if (this->context != nullptr) {
    HMAC_CTX_free(this->context);
  }
}

std::vector<jsi::PropNameID> HmacHostObject::getPropertyNames(jsi::Runtime& rt) {
  std::vector<jsi::PropNameID> result;
  result.push_back(jsi::PropNameID::forUtf8(rt, std::string("update")));
  result.push_back(jsi::PropNameID::forUtf8(rt, std::string("digest")));
  return result;
}

jsi::Value HmacHostObject::get(jsi::Runtime& runtime, const jsi::PropNameID& propNameId) {
  auto propName = propNameId.utf8(runtime);
  auto funcName = "HMAC." + propName;

  // .update(..)
  if (propName == "update") {
    return jsi::Function::createFromHostFunction(runtime,
                                                 jsi::PropNameID::forUtf8(runtime, funcName),
                                                 1,
                                                 [this](jsi::Runtime& runtime,
                                                        const jsi::Value& thisValue,
                                                        const jsi::Value* arguments,
                                                        size_t count) -> jsi::Value {
	if (!arguments[0].isString()) throw jsi::JSError(runtime, "HmacHostObject::update: First argument ('message') has to be of type string!");

	auto message = arguments[0].getString(runtime).utf8(runtime);

	const unsigned char* data = reinterpret_cast<const unsigned char*>(message.c_str());

	HMAC_Update(this->context,
	            data,
	            message.size());

	return jsi::Value::undefined();
      });
  }
  // .digest(..)
  if (propName == "digest") {
    return jsi::Function::createFromHostFunction(runtime,
                                                 jsi::PropNameID::forUtf8(runtime, funcName),
                                                 1,
                                                 [this](jsi::Runtime& runtime,
                                                        const jsi::Value& thisValue,
                                                        const jsi::Value* arguments,
                                                        size_t count) -> jsi::Value {
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
      });
  }

  return jsi::Value::undefined();
}

}
