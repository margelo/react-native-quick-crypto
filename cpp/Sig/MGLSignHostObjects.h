#ifndef MGLSignHostObjects_h
#define MGLSignHostObjects_h

#include <jsi/jsi.h>
#include <openssl/evp.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "MGLKeys.h"
#ifdef ANDROID
#include "JSIUtils/MGLSmartHostObject.h"
#include "Utils/MGLUtils.h"
#else
#include "MGLSmartHostObject.h"
#include "MGLUtils.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

enum DSASigEnc {
  kSigEncDER,
  kSigEncP1363,
};

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

  struct SignResult {
    Error error;
    std::optional<jsi::ArrayBuffer> signature;

    explicit SignResult(Error err,
                        std::optional<jsi::ArrayBuffer> sig = std::nullopt)
        : error(err), signature(std::move(sig)) {}
  };

  void InstallMethods();

  SignResult SignFinal(jsi::Runtime& runtime, const ManagedEVPPKey& pkey,
                       int padding, std::optional<int>& salt_len,
                       DSASigEnc dsa_sig_enc);

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
