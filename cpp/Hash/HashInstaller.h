#include <jsi/jsi.h>
#include "JSI Utils/SmartHostObject.h"

namespace margelo {
namespace jsi = facebook::jsi;

/// It's signature is:
/// createHmac(hashAlgorithm: 'sha1' | 'sha256' | 'sha512',
///            key: string): HMAC
FieldDefinition getHashFieldDefinition(std::shared_ptr<react::CallInvoker> jsCallInvoker,
                                       std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
}  // namespace margelo
