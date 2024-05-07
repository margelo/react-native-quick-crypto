//
//  MGLJSIUtils.h
//  Pods
//
//  Created by Oscar on 20.06.22.
//

#ifndef MGLJSIUtils_h
#define MGLJSIUtils_h

#include <jsi/jsi.h>
#include <limits>

namespace jsi = facebook::jsi;

inline bool CheckIsArrayBuffer(jsi::Runtime &runtime, const jsi::Value &value) {
  return !value.isNull() && !value.isUndefined() && value.isObject() &&
         value.asObject(runtime).isArrayBuffer(runtime);
}

inline bool CheckSizeInt32(jsi::Runtime &runtime, jsi::ArrayBuffer &buffer) {
  return buffer.size(runtime) <= INT_MAX;
}

inline bool CheckIsInt32(const jsi::Value &value) {
  if (!value.isNumber()) {
    return false;
  }
  double d = value.asNumber();
  return (d >= std::numeric_limits<int32_t>::lowest() && d <= std::numeric_limits<int32_t>::max());
}

#endif /* MGLJSIUtils_h */
