//
//  MGLUtils.h
//  Pods
//
//  Created by Oscar on 20.06.22.
//

#ifndef MGLUtils_h
#define MGLUtils_h

#include <openssl/dsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif  // !OPENSSL_NO_ENGINE

#include <memory>
#include <optional>
#include <utility>

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

using EVPKeyPointer = DeleteFnPtr<EVP_PKEY, EVP_PKEY_free>;

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

  //  BignumPointer ToBN() const {
  //    return BignumPointer(BN_bin2bn(data<unsigned char>(), size(), nullptr));
  //  }

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

  //  static ByteSource FromEncodedString(Environment* env,
  //                                      v8::Local<v8::String> value,
  //                                      enum encoding enc = BASE64);
  //
  //  static ByteSource FromStringOrBuffer(Environment* env,
  //                                       v8::Local<v8::Value> value);
  //
  //  static ByteSource FromString(Environment* env,
  //                               v8::Local<v8::String> str,
  //                               bool ntc = false);

  //  static ByteSource FromBuffer(v8::Local<v8::Value> buffer,
  //                               bool ntc = false);

  //  static ByteSource FromBIO(const BIOPointer& bio);
  //
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

int PasswordCallback(char* buf, int size, int rwflag, void* u) {
  const ByteSource* passphrase = *static_cast<const ByteSource**>(u);
  if (passphrase != nullptr) {
    size_t buflen = static_cast<size_t>(size);
    size_t len = passphrase->size();
    if (buflen < len) return -1;
    memcpy(buf, passphrase->data(), len);
    return len;
  }

  return -1;
}

#endif /* MGLUtils_h */
