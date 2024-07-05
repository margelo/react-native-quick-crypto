#include "MGLUtils.h"

#include <jsi/jsi.h>

#include <iostream>
#include <optional>
#include <string>

#include "base64.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

ByteSource ArrayBufferToByteSource(jsi::Runtime& runtime,
                                   const jsi::ArrayBuffer& buffer) {
  if (buffer.size(runtime) == 0) return ByteSource();
  char* buf = MallocOpenSSL<char>(buffer.size(runtime));
  CHECK_NOT_NULL(buf);
  // const cast artificially removes the const qualifier, but you cannot still
  // modify the data in this case, this is safe because we are just memcopying
  // to the buffer
  memcpy(buf, const_cast<jsi::ArrayBuffer&>(buffer).data(runtime),
         buffer.size(runtime));
  return ByteSource::Allocated(buf, buffer.size(runtime));
}

ByteSource ArrayBufferToNTCByteSource(jsi::Runtime& runtime,
                                      const jsi::ArrayBuffer& buffer) {
  if (buffer.size(runtime) == 0) return ByteSource();
  char* buf = MallocOpenSSL<char>(buffer.size(runtime) + 1);
  CHECK_NOT_NULL(buf);
  buf[buffer.size(runtime)] = 0;
  // const cast artificially removes the const qualifier, but you cannot still
  // modify the data in this case, this is safe because we are just memcopying
  // to the buffer
  memcpy(buf, const_cast<jsi::ArrayBuffer&>(buffer).data(runtime),
         buffer.size(runtime));
  return ByteSource::Allocated(buf, buffer.size(runtime));
}

ByteSource::ByteSource(ByteSource&& other) noexcept
    : data_(other.data_),
      allocated_data_(other.allocated_data_),
      size_(other.size_) {
  other.allocated_data_ = nullptr;
}

ByteSource::~ByteSource() { OPENSSL_clear_free(allocated_data_, size_); }

ByteSource& ByteSource::operator=(ByteSource&& other) noexcept {
  if (&other != this) {
    OPENSSL_clear_free(allocated_data_, size_);
    data_ = other.data_;
    allocated_data_ = other.allocated_data_;
    other.allocated_data_ = nullptr;
    size_ = other.size_;
  }
  return *this;
}

// std::unique_ptr<BackingStore> ByteSource::ReleaseToBackingStore() {
//   // It's ok for allocated_data_ to be nullptr but
//   // only if size_ is zero.
//   CHECK_IMPLIES(size_ > 0, allocated_data_ != nullptr);
//   std::unique_ptr<BackingStore> ptr = ArrayBuffer::NewBackingStore(
//                                                                    allocated_data_,
//                                                                    size(),
//                                                                    [](void*
//                                                                    data,
//                                                                    size_t
//                                                                    length,
//                                                                    void*
//                                                                    deleter_data)
//                                                                    {
//                                                                      OPENSSL_clear_free(deleter_data,
//                                                                      length);
//                                                                    },
//                                                                    allocated_data_);
//   CHECK(ptr);
//   allocated_data_ = nullptr;
//   data_ = nullptr;
//   size_ = 0;
//   return ptr;
// }
//
// Local<ArrayBuffer> ByteSource::ToArrayBuffer(Environment* env) {
//   std::unique_ptr<BackingStore> store = ReleaseToBackingStore();
//   return ArrayBuffer::New(env->isolate(), std::move(store));
// }
//
// MaybeLocal<Uint8Array> ByteSource::ToBuffer(Environment* env) {
//   Local<ArrayBuffer> ab = ToArrayBuffer(env);
//   return Buffer::New(env, ab, 0, ab->ByteLength());
// }

ByteSource ByteSource::FromBIO(const BIOPointer& bio) {
//  CHECK(bio);
  BUF_MEM* bptr;
  BIO_get_mem_ptr(bio.get(), &bptr);
  ByteSource::Builder out(bptr->length);
  memcpy(out.data<void>(), bptr->data, bptr->length);
  return std::move(out).release();
}

ByteSource ByteSource::FromEncodedString(jsi::Runtime &rt,
                                         const std::string key,
                                         enum encoding enc) {
  // memcpy & size together properly handle strings containing \0 characters
  std::string result = StringBytesWrite(rt, key, enc);
  size_t size = result.size();
  ByteSource::Builder out(size);
  memcpy(out.data<void>(), result.data(), size);
  return std::move(out).release(size);
}

ByteSource ByteSource::FromStringOrBuffer(jsi::Runtime& runtime,
                                          const jsi::Value& value) {
  return value.isString()
             ? FromString(value.asString(runtime).utf8(runtime))
             : FromBuffer(runtime,
                          value.asObject(runtime).getArrayBuffer(runtime));
}

// ntc = null terminated copy
ByteSource ByteSource::FromString(std::string str, bool ntc) {
  //   CHECK(str->IsString());
  size_t size = str.size();
  size_t alloc_size = ntc ? size + 1 : size;
  ByteSource::Builder out(alloc_size);
  if (ntc) {
    strcpy(out.data<char>(), str.data());
  } else {
    strncpy(out.data<char>(), str.data(), alloc_size);
  }

  return std::move(out).release(alloc_size);
}

ByteSource ByteSource::FromBuffer(jsi::Runtime& runtime,
                                  const jsi::ArrayBuffer& buffer, bool ntc) {
  return ntc ? ArrayBufferToNTCByteSource(runtime, buffer)
             : ArrayBufferToByteSource(runtime, buffer);
}
//
// ByteSource ByteSource::FromSecretKeyBytes(
//                                           Environment* env,
//                                           Local<Value> value) {
//   // A key can be passed as a string, buffer or KeyObject with type
//   'secret'.
//   // If it is a string, we need to convert it to a buffer. We are not doing
//   that
//   // in JS to avoid creating an unprotected copy on the heap.
//   return value->IsString() || IsAnyByteSource(value) ?
//   ByteSource::FromStringOrBuffer(env, value) :
//   ByteSource::FromSymmetricKeyObjectHandle(value);
// }

// ByteSource ByteSource::NullTerminatedCopy(Environment* env,
//                                           Local<Value> value) {
//   return Buffer::HasInstance(value) ? FromBuffer(value, true)
//   : FromString(env, value.As<String>(), true);
// }

// ByteSource ByteSource::FromSymmetricKeyObjectHandle(Local<Value> handle) {
//   CHECK(handle->IsObject());
//   KeyObjectHandle* key = Unwrap<KeyObjectHandle>(handle.As<Object>());
//   CHECK_NOT_NULL(key);
//   return Foreign(key->Data()->GetSymmetricKey(),
//                  key->Data()->GetSymmetricKeySize());
// }

ByteSource ByteSource::Allocated(void* data, size_t size) {
  return ByteSource(data, data, size);
}

ByteSource ByteSource::Foreign(const void* data, size_t size) {
  return ByteSource(data, nullptr, size);
}

ByteSource ByteSource::FromBN(const BIGNUM* bn, size_t size) {
  std::vector<uint8_t> buf(size);
  CHECK_EQ(BN_bn2binpad(bn, buf.data(), size), size);
  ByteSource::Builder out(size);
  memcpy(out.data<void>(), buf.data(), size);
  return std::move(out).release();
}

ByteSource GetByteSourceFromJS(jsi::Runtime &rt,
                               const jsi::Value &value,
                               std::string name) {
    if (!value.isObject() || !value.asObject(rt).isArrayBuffer(rt)) {
    throw jsi::JSError(rt, "arg is not an array buffer: " + name);
  }
  ByteSource data = ByteSource::FromStringOrBuffer(rt, value);
  if (data.size() > INT_MAX) {
    throw jsi::JSError(rt, "arg is too big (> int32): " + name);
  }
  return data;
}

std::string EncodeBignum(const BIGNUM* bn,
                         size_t size,
                         bool url) {
  if (size == 0)
    size = BN_num_bytes(bn);
  std::vector<uint8_t> buf(size);
  CHECK_EQ(BN_bn2binpad(bn, buf.data(), size), size);
  std::string data(buf.begin(), buf.end());
  return EncodeBase64(data, url);
}

// loosely based on Node src/string_bytes.cc - StringBytes::Write()
std::string StringBytesWrite(jsi::Runtime &rt,
                             const std::string val,
                             enum encoding encoding) {
  std::string result;

  switch (encoding) {
    case BASE64:
      // fallthrough
    case BASE64URL:
      result = DecodeBase64(val);
      break;
    default:
      throw jsi::JSError(rt, "Encoding not supported");
  }

  return result;
}

std::string EncodeBase64(const std::string data, bool url) {
  return base64_encode(data, url);
}

std::string DecodeBase64(const std::string &in, bool remove_linebreaks) {
  return base64_decode(in, remove_linebreaks);
}

MUST_USE_RESULT CSPRNGResult CSPRNG(void* buffer, size_t length) {
  unsigned char* buf = static_cast<unsigned char*>(buffer);
  do {
    if (1 == RAND_status()) {
#if OPENSSL_VERSION_MAJOR >= 3
      if (1 == RAND_bytes_ex(nullptr, buf, length, 0)) return {true};
#else
      while (length > INT_MAX && 1 == RAND_bytes(buf, INT_MAX)) {
        buf += INT_MAX;
        length -= INT_MAX;
      }
      if (length <= INT_MAX && 1 == RAND_bytes(buf, static_cast<int>(length)))
        return {true};
#endif
    }
#if OPENSSL_VERSION_MAJOR >= 3
    const auto code = ERR_peek_last_error();
    // A misconfigured OpenSSL 3 installation may report 1 from RAND_poll()
    // and RAND_status() but fail in RAND_bytes() if it cannot look up
    // a matching algorithm for the CSPRNG.
    if (ERR_GET_LIB(code) == ERR_LIB_RAND) {
      const auto reason = ERR_GET_REASON(code);
      if (reason == RAND_R_ERROR_INSTANTIATING_DRBG ||
          reason == RAND_R_UNABLE_TO_FETCH_DRBG ||
          reason == RAND_R_UNABLE_TO_CREATE_DRBG) {
        return {false};
      }
    }
#endif
  } while (1 == RAND_poll());

  return {false};
}

bool SetRsaOaepLabel(const EVPKeyCtxPointer& ctx, const ByteSource& label) {
  if (label.size() != 0) {
    // OpenSSL takes ownership of the label, so we need to create a copy.
    void* label_copy = OPENSSL_memdup(label.data(), label.size());
    CHECK_NOT_NULL(label_copy);
    int ret = EVP_PKEY_CTX_set0_rsa_oaep_label(
        ctx.get(), static_cast<unsigned char*>(label_copy), label.size());
    if (ret <= 0) {
      OPENSSL_free(label_copy);
      return false;
    }
  }
  return true;
}

}  // namespace margelo
