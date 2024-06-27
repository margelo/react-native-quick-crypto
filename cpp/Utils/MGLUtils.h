#ifndef MGLUtils_h
#define MGLUtils_h

#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif  // !OPENSSL_NO_ENGINE

#include <jsi/jsi.h>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <variant>

#ifdef ANDROID
#include "Utils/node.h"
#else
#include "node.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

template <typename T, void (*function)(T*)>
struct FunctionDeleter {
    void operator()(T* pointer) const { function(pointer); }
    typedef std::unique_ptr<T, FunctionDeleter> Pointer;
};

template <typename T, void (*function)(T*)>
using DeleteFnPtr = typename FunctionDeleter<T, function>::Pointer;
using X509Pointer = DeleteFnPtr<X509, X509_free>;
using BIOPointer = DeleteFnPtr<BIO, BIO_free_all>;
using PKCS8Pointer = DeleteFnPtr<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free>;
using EVPKeyCtxPointer = DeleteFnPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free>;
using EVPKeyPointer = DeleteFnPtr<EVP_PKEY, EVP_PKEY_free>;
using BignumPointer = DeleteFnPtr<BIGNUM, BN_free>;
using RsaPointer = DeleteFnPtr<RSA, RSA_free>;
using EVPMDPointer = DeleteFnPtr<EVP_MD_CTX, EVP_MD_CTX_free>;
using ECDSASigPointer = DeleteFnPtr<ECDSA_SIG, ECDSA_SIG_free>;
using ECKeyPointer = DeleteFnPtr<EC_KEY, EC_KEY_free>;
using ECPointPointer = DeleteFnPtr<EC_POINT, EC_POINT_free>;
using CipherCtxPointer = DeleteFnPtr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_free>;


#ifdef __GNUC__
#define MUST_USE_RESULT __attribute__((warn_unused_result))
#else
#define MUST_USE_RESULT
#endif

struct CSPRNGResult {
  const bool ok;
  MUST_USE_RESULT bool is_ok() const { return ok; }
  MUST_USE_RESULT bool is_err() const { return !ok; }
};

// Either succeeds with exactly |length| bytes of cryptographically
// strong pseudo-random data, or fails. This function may block.
// Don't assume anything about the contents of |buffer| on error.
// As a special case, |length == 0| can be used to check if the CSPRNG
// is properly seeded without consuming entropy.
MUST_USE_RESULT CSPRNGResult CSPRNG(void* buffer, size_t length);

template <typename T>
class NonCopyableMaybe {
 public:
    NonCopyableMaybe() : empty_(true) {}
    explicit NonCopyableMaybe(T&& value)
    : empty_(false), value_(std::move(value)) {}

    bool IsEmpty() const { return empty_; }

    const T* get() const { return empty_ ? nullptr : &value_; }

    const T* operator->() const {
        //    CHECK(!empty_);
        return &value_;
    }

    T&& Release() {
        //    CHECK_EQ(empty_, false);
        empty_ = true;
        return std::move(value_);
    }

 private:
    bool empty_;
    T value_;
};

template <typename T>
inline T MultiplyWithOverflowCheck(T a, T b) {
    auto ret = a * b;
    //  if (a != 0)
    //    CHECK_EQ(b, ret / a);

    return ret;
}

template <typename T>
T* MallocOpenSSL(size_t count) {
    void* mem = OPENSSL_malloc(MultiplyWithOverflowCheck(count, sizeof(T)));
    //  CHECK_IMPLIES(mem == nullptr, count == 0);
    return static_cast<T*>(mem);
}

// A helper class representing a read-only byte array. When deallocated, its
// contents are zeroed.
class ByteSource {
 public:
    class Builder {
     public:
        // Allocates memory using OpenSSL's memory allocator.
        explicit Builder(size_t size)
        : data_(MallocOpenSSL<char>(size)), size_(size) {}

        Builder(Builder&& other) = delete;
        Builder& operator=(Builder&& other) = delete;
        Builder(const Builder&) = delete;
        Builder& operator=(const Builder&) = delete;

        ~Builder() { OPENSSL_clear_free(data_, size_); }

        // Returns the underlying non-const pointer.
        template <typename T>
        T* data() {
            return reinterpret_cast<T*>(data_);
        }

        // Returns the (allocated) size in bytes.
        size_t size() const { return size_; }

        // Finalizes the Builder and returns a read-only view that is optionally
        // truncated.
        ByteSource release(std::optional<size_t> resize = std::nullopt) && {
            if (resize) {
                //        CHECK_LE(*resize, size_);
                if (*resize == 0) {
                    OPENSSL_clear_free(data_, size_);
                    data_ = nullptr;
                }
                size_ = *resize;
            }
            ByteSource out = ByteSource::Allocated(data_, size_);
            data_ = nullptr;
            size_ = 0;
            return out;
        }

     private:
        void* data_;
        size_t size_;
    };

    ByteSource() = default;
    ByteSource(ByteSource&& other) noexcept;
    ~ByteSource();

    ByteSource& operator=(ByteSource&& other) noexcept;

    ByteSource(const ByteSource&) = delete;
    ByteSource& operator=(const ByteSource&) = delete;

    template <typename T = void>
    const T* data() const {
        return reinterpret_cast<const T*>(data_);
    }

    size_t size() const { return size_; }

    operator bool() const { return data_ != nullptr; }

    inline BignumPointer ToBN() const {
        return BignumPointer(BN_bin2bn(data<unsigned char>(), (int)size(), nullptr));
    }

    inline std::string ToString() const {
        std::vector<uint8_t> buf(size_);
        std::memcpy(&buf[0], data_, size_);
        std::string ret(buf.begin(), buf.end());
        return ret;
    }

    // Creates a v8::BackingStore that takes over responsibility for
    // any allocated data. The ByteSource will be reset with size = 0
    // after being called.
    //  std::unique_ptr<v8::BackingStore> ReleaseToBackingStore();
    //
    //  v8::Local<v8::ArrayBuffer> ToArrayBuffer(Environment* env);
    //
    //  v8::MaybeLocal<v8::Uint8Array> ToBuffer(Environment* env);

    static ByteSource Allocated(void* data, size_t size);
    static ByteSource Foreign(const void* data, size_t size);

     static ByteSource FromEncodedString(jsi::Runtime &rt,
                                         std::string value,
                                         enum encoding enc = BASE64);

    static ByteSource FromStringOrBuffer(jsi::Runtime& runtime,
                                         const jsi::Value& value);

    static ByteSource FromString(std::string str, bool ntc = false);

    static ByteSource FromBuffer(jsi::Runtime& runtime,
                                 const jsi::ArrayBuffer& buffer,
                                 bool ntc = false);

    static ByteSource FromBIO(const BIOPointer& bio);

    //  static ByteSource NullTerminatedCopy(Environment* env,
    //                                       v8::Local<v8::Value> value);
    //
    //  static ByteSource FromSymmetricKeyObjectHandle(v8::Local<v8::Value>
    //  handle);

    //  static ByteSource FromSecretKeyBytes(
    //                                       Environment* env,
    //                                       v8::Local<v8::Value> value);

 private:
    const void* data_ = nullptr;
    void* allocated_data_ = nullptr;
    size_t size_ = 0;

    ByteSource(const void* data, void* allocated_data, size_t size)
    : data_(data), allocated_data_(allocated_data), size_(size) {}
};

ByteSource ArrayBufferToByteSource(jsi::Runtime& runtime,
                                   const jsi::ArrayBuffer& buffer);

ByteSource ArrayBufferToNTCByteSource(jsi::Runtime& runtime,
                                      const jsi::ArrayBuffer& buffer);

// Originally part of the ArrayBufferContentOrView class
inline ByteSource ToNullTerminatedByteSource(jsi::Runtime& runtime,
                                             jsi::ArrayBuffer& buffer) {
    if (buffer.size(runtime) == 0) return ByteSource();
    char* buf = MallocOpenSSL<char>(buffer.size(runtime) + 1);
    //    CHECK_NOT_NULL(buf);
    buf[buffer.size(runtime)] = 0;
    memcpy(buf, buffer.data(runtime), buffer.size(runtime));
    return ByteSource::Allocated(buf, buffer.size(runtime));
}

inline int PasswordCallback(char* buf, int size, int rwflag, void* u) {
    const ByteSource* passphrase = *static_cast<const ByteSource**>(u);
    if (passphrase != nullptr) {
        size_t buflen = static_cast<size_t>(size);
        size_t len = passphrase->size();
        if (buflen < len) return -1;
        memcpy(buf, passphrase->data(), len);
        return (int)len;
    }

    return -1;
}

inline void CheckEntropy() {
    for (;;) {
        int status = RAND_status();
        //    CHECK_GE(status, 0);  // Cannot fail.
        if (status != 0) break;

        // Give up, RAND_poll() not supported.
        if (RAND_poll() == 0) break;
    }
}

std::string StringBytesWrite(jsi::Runtime &rt,
                        const std::string val,
                        enum encoding encoding);


inline jsi::Value toJSI(jsi::Runtime& rt, std::string value) {
  return jsi::String::createFromUtf8(rt, value);
}

inline jsi::Value toJSI(jsi::Runtime& rt, ByteSource value) {
    jsi::Function array_buffer_ctor =
        rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
    jsi::Object o = array_buffer_ctor.callAsConstructor(rt, (int)value.size())
                        .getObject(rt);
    jsi::ArrayBuffer buf = o.getArrayBuffer(rt);
    // You cannot share raw memory between native and JS
    // always copy the data
    // see https://github.com/facebook/hermes/pull/419 and
    // https://github.com/facebook/hermes/issues/564.
    memcpy(buf.data(rt), value.data(), value.size());
    return o;
}

std::string EncodeBignum(const BIGNUM* bn,
                         int size,
                         bool url = false);

std::string EncodeBase64(const std::string data, bool url = false);
std::string DecodeBase64(const std::string &in, bool remove_linebreaks = false);

// TODO: until shared, keep in sync with JS side (src/NativeQuickCrypto/Cipher.ts)
enum KeyVariant {
  kvRSA_SSA_PKCS1_v1_5,
  kvRSA_PSS,
  kvRSA_OAEP,
  kvDSA,
  kvEC,
  kvNID,
  kvDH,
};

enum FnMode {
  kAsync,
  kSync,
};

}  // namespace margelo

#endif /* MGLUtils_h */
