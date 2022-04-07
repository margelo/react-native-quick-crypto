//
// Created by Szymon on 24/02/2022.
//

#ifndef FASTCRYPTOEXAMPLE_JSIMACROS_H
#define FASTCRYPTOEXAMPLE_JSIMACROS_H

// if you want to create a new marco use (https://godbolt.org) provide flag -E in right panel

#define HOST_LAMBDA(name, body) HOST_LAMBDA_CAP(name, [=], body)

#define HOST_LAMBDA_CAP(name, capture, body) std::make_pair(name, capture(jsi::Runtime & runtime) { \
    const auto func = capture(jsi::Runtime &runtime, const jsi::Value &thisValue, \
                              const jsi::Value *arguments, size_t count)->jsi::Value  \
                      body; \
    auto propNameID = jsi::PropNameID::forAscii(runtime, name); \
    return jsi::Function::createFromHostFunction(runtime, propNameID, 0, func); \
  })

#define JSI_VALUE(name, body) JSI_VALUE_CAP(name, [=], body)

#define JSI_VALUE_CAP(name, capture, body) std::make_pair(name, capture(jsi::Runtime & runtime) \
                                                          body \
                                                          )

#define JSIF(capture) capture(jsi::Runtime &runtime, const jsi::Value &thisValue, \
                              const jsi::Value *arguments, size_t count)->jsi::Value

#endif //FASTCRYPTOEXAMPLE_JSIMACROS_H
