//
// Created by Szymon on 25/02/2022.
//

#ifndef FASTCRYPTOEXAMPLE_RANDOMHOSTOBJECT_H
#define FASTCRYPTOEXAMPLE_RANDOMHOSTOBJECT_H

#include "JSI Utils/SmartHostObject.h"

namespace margelo {
namespace jsi = facebook::jsi;

class RandomHostObject : public SmartHostObject {
public:
RandomHostObject(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                 std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
};

}  // namespace margelo
#endif  // FASTCRYPTOEXAMPLE_RANDOMHOSTOBJECT_H
