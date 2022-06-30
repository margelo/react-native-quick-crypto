#ifndef MGLSignHostObjects_h
#define MGLSignHostObjects_h

#include <jsi/jsi.h>
#include <openssl/evp.h>

#include <memory>
#include <string>

#ifdef ANDROID
#include "JSIUtils/MGLSmartHostObject.h"
#include "Utils/MGLUtils.h"
#else
#include "MGLSmartHostObject.h"
#include "MGLUtils.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

class SignBase : public MGLSmartHostObject {
 public:
  SignBase(std::shared_ptr<react::CallInvoker> jsCallInvoker,
           std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);

  typedef enum {
    kSignOk,
    kSignUnknownDigest,
    kSignInit,
    kSignNotInitialised,
    kSignUpdate,
    kSignPrivateKey,
    kSignPublicKey,
    kSignMalformedSignature
  } Error;

  void InstallMethods();

  //  Error Init(const char* sign_type);
  //  Error Update(const char* data, size_t len);
 protected:
  EVPMDPointer mdctx_;
};

class MGLSignHostObject : public SignBase {
 public:
  explicit MGLSignHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
  //
  //  explicit MGLSignHostObject(
  //                               MGLSignHostObject *other,
  //                               std::shared_ptr<react::CallInvoker>
  //                               jsCallInvoker,
  //                               std::shared_ptr<DispatchQueue::dispatch_queue>
  //                               workerQueue);

 protected:
  //  static void New
  //  static void SignInit
  //  static void SignUpdate
  //  static void SignFinal

  //  Sign
};

}  // namespace margelo

#endif /* MGLSignHostObject_h */
