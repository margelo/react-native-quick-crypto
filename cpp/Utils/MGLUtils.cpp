#include "MGLUtils.h"

#include <jsi/jsi.h>

#include <string>

#ifdef ANDROID
#include "JSIUtils/MGLJSIMacros.h"
#else
#include "MGLJSIMacros.h"
#endif

namespace margelo {

namespace jsi = facebook::jsi;

jsi::Object ByteSourceToArrayBuffer(jsi::Runtime &rt,
                                         ByteSource &source) {
    jsi::Function array_buffer_ctor = rt.global().getPropertyAsFunction(rt, "ArrayBuffer");
    jsi::Object o = array_buffer_ctor.callAsConstructor(rt, (int)source.size()).getObject(rt);
    jsi::ArrayBuffer buf = o.getArrayBuffer(rt);
    // You cannot share raw memory between native and JS
    // always copy the data
    // see https://github.com/facebook/hermes/pull/419 and https://github.com/facebook/hermes/issues/564.
    memcpy(buf.data(rt), source.data(), source.size());
    return o;
}

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

// ByteSource ByteSource::FromEncodedString(Environment* env,
//                                          Local<String> key,
//                                          enum encoding enc) {
//   size_t length = 0;
//   ByteSource out;
//
//   if (StringBytes::Size(env->isolate(), key, enc).To(&length) && length >
//   0)
//   {
//     ByteSource::Builder buf(length);
//     size_t actual =
//     StringBytes::Write(env->isolate(), buf.data<char>(), length, key, enc);
//     out = std::move(buf).release(actual);
//   }
//
//   return out;
// }
//
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
  //   int opts = String::NO_OPTIONS;
  //   if (!ntc) opts |= String::NO_NULL_TERMINATION;
  //   str->WriteUtf8(env->isolate(), out.data<char>(), alloc_size, nullptr,
  //   opts);
  if (ntc) {
    strcpy(out.data<char>(), str.data());
  } else {
    strncpy(out.data<char>(), str.data(), alloc_size);
  }

  return std::move(out).release();
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

}  // namespace margelo
