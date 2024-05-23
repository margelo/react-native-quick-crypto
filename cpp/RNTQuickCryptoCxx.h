/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#if __has_include(<ReactCodegen/AppSpecsJSI.h>) // CocoaPod headers on Apple
#include <ReactCodegen/AppSpecsJSI.h>
#elif __has_include("AppSpecsJSI.h") // Cmake headers on Android
#include "AppSpecsJSI.h"
#else // BUCK headers
#include "RTNQuickCryptoCxxSpecJSI.h"
#endif
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace facebook::react {

#pragma mark - implementation
class RNTQuickCryptoCxx : public NativeQuickCryptoCxxCxxSpec<RNTQuickCryptoCxx> {
 public:
  RNTQuickCryptoCxx(std::shared_ptr<CallInvoker> jsInvoker);
  virtual ~RNTQuickCryptoCxx() = default;
    
  double install(jsi::Runtime &rt, double a, double b);
};

} // namespace facebook::react
