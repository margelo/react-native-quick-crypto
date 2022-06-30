//
//  MGLJSIUtils.h
//  Pods
//
//  Created by Oscar on 20.06.22.
//

#ifndef MGLJSIUtils_h
#define MGLJSIUtils_h

#include <jsi/jsi.h>

namespace jsi = facebook::jsi;

inline bool CheckIsArrayBuffer(jsi::Runtime &runtime, const jsi::Value &value) {
  return !value.isNull() && !value.isUndefined() && value.isObject() &&
         value.asObject(runtime).isArrayBuffer(runtime);
}

inline bool CheckSizeInt32(jsi::Runtime &runtime, jsi::ArrayBuffer &buffer) {
  return buffer.size(runtime) <= INT_MAX;
}

#endif /* MGLJSIUtils_h */
