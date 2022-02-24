//
//  fastpbkdf2-JSI-Installer.m
//  PinkPanda
//
//  Created by Marc Rousavy on 31.10.21.
//

#include "fastpbkdf2-JSI-Installer.h"

#include "fastpbkdf2.h"
#include "../../../../Downloads/cpp/JSI Utils/TypedArray.h"

using namespace facebook;

namespace fastpbkdf2 {

void installInRuntime(jsi::Runtime& runtime) {
  // fastkbdf2(password: BytesLike,
  //           salt: BytesLike,
  //           iterations: number,
  //           keyLength: number,
  //           hashAlgorithm: 'sha1' | 'sha256' | 'sha512')
  auto func = jsi::Function::createFromHostFunction(runtime,
                                                    jsi::PropNameID::forAscii(runtime, "func"),
                                                    5,
                                                    [](jsi::Runtime& runtime,
                                                       const jsi::Value&,
                                                       const jsi::Value* arguments,
                                                       size_t count) -> jsi::Value {
      if (count != 5) {
	throw jsi::JSError(runtime, "fastpbkdf2(..) expects exactly 5 arguments!");
      }

      auto password = arguments[0].asObject(runtime).getArrayBuffer(runtime);
      auto salt = arguments[1].asObject(runtime).getArrayBuffer(runtime);
      auto iterations = arguments[2].asNumber();
      auto keyLength = arguments[3].asNumber();
      auto hashAlgorithm = arguments[4].asString(runtime).utf8(runtime);

      auto resultArray = TypedArray<TypedArrayKind::Uint8Array>(runtime, static_cast<size_t>(keyLength));
      auto result = resultArray.getBuffer(runtime);

      if (hashAlgorithm == "sha1") {
	fastpbkdf2_hmac_sha1(password.data(runtime), password.size(runtime),
	                     salt.data(runtime), salt.size(runtime),
	                     static_cast<uint32_t>(iterations),
	                     result.data(runtime), result.size(runtime));
      } else if (hashAlgorithm == "sha256") {
	fastpbkdf2_hmac_sha256(password.data(runtime), password.size(runtime),
	                       salt.data(runtime), salt.size(runtime),
	                       static_cast<uint32_t>(iterations),
	                       result.data(runtime), result.size(runtime));
      } else if (hashAlgorithm == "sha512") {
	fastpbkdf2_hmac_sha512(password.data(runtime), password.size(runtime),
	                       salt.data(runtime), salt.size(runtime),
	                       static_cast<uint32_t>(iterations),
	                       result.data(runtime), result.size(runtime));
      } else {
	throw jsi::JSError(runtime, "Invalid hash-algorithm!");
      }

      return resultArray;
    });
  runtime.global().setProperty(runtime, "pbkdf2", std::move(func));
}
}
