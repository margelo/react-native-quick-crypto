//
//  MGLUtils.cpp
//  react-native-quick-crypto
//
//  Created by Oscar on 21.06.22.
//

#include "MGLUtils.h"

#include <jsi/jsi.h>

namespace margelo {

namespace jsi = facebook::jsi;

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

// ByteSource ByteSource::FromBIO(const BIOPointer& bio) {
////  CHECK(bio);
//  BUF_MEM* bptr;
//  BIO_get_mem_ptr(bio.get(), &bptr);
//  ByteSource::Builder out(bptr->length);
//  memcpy(out.data<void>(), bptr->data, bptr->length);
//  return std::move(out).release();
//}

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
// ByteSource ByteSource::FromStringOrBuffer(Environment* env,
//                                           Local<Value> value) {
//   return IsAnyByteSource(value) ? FromBuffer(value)
//   : FromString(env, value.As<String>());
// }
//
// ByteSource ByteSource::FromString(Environment* env, Local<String> str,
//                                   bool ntc) {
//   CHECK(str->IsString());
//   size_t size = str->Utf8Length(env->isolate());
//   size_t alloc_size = ntc ? size + 1 : size;
//   ByteSource::Builder out(alloc_size);
//   int opts = String::NO_OPTIONS;
//   if (!ntc) opts |= String::NO_NULL_TERMINATION;
//   str->WriteUtf8(env->isolate(), out.data<char>(), alloc_size, nullptr,
//   opts); return std::move(out).release();
// }
//
// ByteSource ByteSource::FromBuffer(Local<Value> buffer, bool ntc) {
//   ArrayBufferOrViewContents<char> buf(buffer);
//   return ntc ? buf.ToNullTerminatedCopy() : buf.ToByteSource();
// }
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
