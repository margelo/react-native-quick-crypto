//
//  MGLSignInstaller.hpp
//  DoubleConversion
//
//  Created by Oscar on 30.06.22.
//

#ifndef MGLSignInstaller_h
#define MGLSignInstaller_h

#include <jsi/jsi.h>

#include <memory>

#ifdef ANDROID
#include "JSIUtils/MGLSmartHostObject.h"
#else
#include "MGLSmartHostObject.h"
#endif

namespace margelo {
namespace jsi = facebook::jsi;

FieldDefinition getCreateSignFieldDefinition(
    std::shared_ptr<react::CallInvoker> jsCallInvoker,
    std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo

#endif /* MGLSignInstaller_h */
