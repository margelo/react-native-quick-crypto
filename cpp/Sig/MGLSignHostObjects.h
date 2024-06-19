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

static const unsigned int kNoDsaSignature = static_cast<unsigned int>(-1);

enum mode { kModeSign, kModeVerify };

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
    std::optional<jsi::Value> signature;

    explicit SignResult(Error err, std::optional<jsi::Value> sig = std::nullopt)
        : error(err), signature(std::move(sig)) {}
  };

  void InstallMethods(mode);

  SignResult SignFinal(jsi::Runtime& runtime, const ManagedEVPPKey& pkey,
                       int padding, std::optional<int>& salt_len,
                       DSASigEnc dsa_sig_enc);

  Error VerifyFinal(const ManagedEVPPKey& pkey, const ByteSource& sig,
                    int padding, std::optional<int>& saltlen,
                    bool* verify_result);

 protected:
  EVPMDPointer mdctx_;
};

struct SignConfiguration final {  //  : public MemoryRetainer
  enum Mode {
    kSign,
    kVerify
  };
  enum Flags {
    kHasNone = 0,
    kHasSaltLength = 1,
    kHasPadding = 2
  };

  // CryptoJobMode job_mode;  // all async for now
  Mode mode;
  ManagedEVPPKey key;
  ByteSource data;
  ByteSource signature;
  const EVP_MD* digest = nullptr;
  int flags = SignConfiguration::kHasNone;
  int padding = 0;
  int salt_length = 0;
  DSASigEnc dsa_encoding = kSigEncDER;

  SignConfiguration() = default;

  // explicit SignConfiguration(SignConfiguration&& other) noexcept;

  // SignConfiguration& operator=(SignConfiguration&& other) noexcept;

  // void MemoryInfo(MemoryTracker* tracker) const override;
  // SET_MEMORY_INFO_NAME(SignConfiguration)
  // SET_SELF_SIZE(SignConfiguration)
};

class SubtleSignVerify {
  public:
    SignConfiguration GetParamsFromJS(jsi::Runtime &rt, const jsi::Value *args);
    void DoSignVerify(jsi::Runtime &rt, const SignConfiguration &params, ByteSource &out);
    jsi::Value EncodeOutput(jsi::Runtime &rt,const SignConfiguration &params, ByteSource &out);
};

class MGLSignHostObject : public SignBase {
 public:
  explicit MGLSignHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
};

class MGLVerifyHostObject : public SignBase {
 public:
  explicit MGLVerifyHostObject(
      std::shared_ptr<react::CallInvoker> jsCallInvoker,
      std::shared_ptr<DispatchQueue::dispatch_queue> workerQueue);
};

}  // namespace margelo

#endif /* MGLSignHostObjects_h */
