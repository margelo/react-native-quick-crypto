/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include "RTNQuickCryptoCxxSpecJSI.h"
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>


namespace facebook::react {

namespace margelo {

#pragma mark - implementation
class RNTQuickCryptoCxx : public NativeQuickCryptoCxxCxxSpec<RNTQuickCryptoCxx> {
public:
    RNTQuickCryptoCxx(std::shared_ptr<CallInvoker> jsInvoker);
    virtual ~RNTQuickCryptoCxx() = default;
    
    double install(jsi::Runtime &rt);
};
}
} // namespace facebook::react

