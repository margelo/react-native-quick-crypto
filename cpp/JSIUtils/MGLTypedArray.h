//
//  TypedArray.h
//  react-native-fast-crypto
//
//  Created by Marc Rousavy on 31.10.21.
//  Originally created by Expo (expo-gl)
//

#pragma once

#include <jsi/jsi.h>

#include <utility>
#include <vector>

namespace jsi = facebook::jsi;

enum class MGLTypedArrayKind {
  Int8Array,
  Int16Array,
  Int32Array,
  Uint8Array,
  Uint8ClampedArray,
  Uint16Array,
  Uint32Array,
  Float32Array,
  Float64Array,
};

template <MGLTypedArrayKind T>
class MGLTypedArray;

template <MGLTypedArrayKind T>
struct typedArrayTypeMap;
template <>
struct typedArrayTypeMap<MGLTypedArrayKind::Int8Array> {
  typedef int8_t type;
};
template <>
struct typedArrayTypeMap<MGLTypedArrayKind::Int16Array> {
  typedef int16_t type;
};
template <>
struct typedArrayTypeMap<MGLTypedArrayKind::Int32Array> {
  typedef int32_t type;
};
template <>
struct typedArrayTypeMap<MGLTypedArrayKind::Uint8Array> {
  typedef uint8_t type;
};
template <>
struct typedArrayTypeMap<MGLTypedArrayKind::Uint8ClampedArray> {
  typedef uint8_t type;
};
template <>
struct typedArrayTypeMap<MGLTypedArrayKind::Uint16Array> {
  typedef uint16_t type;
};
template <>
struct typedArrayTypeMap<MGLTypedArrayKind::Uint32Array> {
  typedef uint32_t type;
};
template <>
struct typedArrayTypeMap<MGLTypedArrayKind::Float32Array> {
  typedef float type;
};
template <>
struct typedArrayTypeMap<MGLTypedArrayKind::Float64Array> {
  typedef double type;
};

void invalidateJsiPropNameIDCache();

class MGLTypedArrayBase : public jsi::Object {
 public:
  template <MGLTypedArrayKind T>
  using ContentType = typename typedArrayTypeMap<T>::type;

  MGLTypedArrayBase(jsi::Runtime &, size_t, MGLTypedArrayKind);
  MGLTypedArrayBase(jsi::Runtime &, const jsi::Object &);
  MGLTypedArrayBase(MGLTypedArrayBase &&) = default;
  MGLTypedArrayBase &operator=(MGLTypedArrayBase &&) = default;

  MGLTypedArrayKind getKind(jsi::Runtime &runtime) const;

  template <MGLTypedArrayKind T>
  MGLTypedArray<T> get(jsi::Runtime &runtime) const &;
  template <MGLTypedArrayKind T>
  MGLTypedArray<T> get(jsi::Runtime &runtime) &&;
  template <MGLTypedArrayKind T>
  MGLTypedArray<T> as(jsi::Runtime &runtime) const &;
  template <MGLTypedArrayKind T>
  MGLTypedArray<T> as(jsi::Runtime &runtime) &&;

  size_t size(jsi::Runtime &runtime) const;
  size_t length(jsi::Runtime &runtime) const;
  size_t byteLength(jsi::Runtime &runtime) const;
  size_t byteOffset(jsi::Runtime &runtime) const;
  bool hasBuffer(jsi::Runtime &runtime) const;

  std::vector<uint8_t> toVector(jsi::Runtime &runtime);
  jsi::ArrayBuffer getBuffer(jsi::Runtime &runtime) const;

 private:
  template <MGLTypedArrayKind>
  friend class MGLTypedArray;
};

bool isTypedArray(jsi::Runtime &runtime, const jsi::Object &jsObj);
MGLTypedArrayBase getTypedArray(jsi::Runtime &runtime,
                                const jsi::Object &jsObj);

std::vector<uint8_t> arrayBufferToVector(jsi::Runtime &runtime,
                                         jsi::Object &jsObj);
void arrayBufferUpdate(jsi::Runtime &runtime, jsi::ArrayBuffer &buffer,
                       std::vector<uint8_t> data, size_t offset);

template <MGLTypedArrayKind T>
class MGLTypedArray : public MGLTypedArrayBase {
 public:
  MGLTypedArray(jsi::Runtime &runtime, size_t size);
  MGLTypedArray(jsi::Runtime &runtime, std::vector<ContentType<T>> data);
  explicit MGLTypedArray(MGLTypedArrayBase &&base);
  explicit MGLTypedArray(MGLTypedArray &&) = default;
  MGLTypedArray &operator=(MGLTypedArray &&) = default;

  std::vector<ContentType<T>> toVector(jsi::Runtime &runtime);
  void update(jsi::Runtime &runtime, const std::vector<ContentType<T>> &data);
};

template <MGLTypedArrayKind T>
MGLTypedArray<T> MGLTypedArrayBase::get(jsi::Runtime &runtime) const & {
  assert(getKind(runtime) == T);
  (void)runtime;  // when assert is disabled we need to mark this as used
  return MGLTypedArray<T>(
      jsi::Value(runtime, jsi::Value(runtime, *this).asObject(runtime)));
}

template <MGLTypedArrayKind T>
MGLTypedArray<T> MGLTypedArrayBase::get(jsi::Runtime &runtime) && {
  assert(getKind(runtime) == T);
  (void)runtime;  // when assert is disabled we need to mark this as used
  return MGLTypedArray<T>(std::move(*this));
}

template <MGLTypedArrayKind T>
MGLTypedArray<T> MGLTypedArrayBase::as(jsi::Runtime &runtime) const & {
  if (getKind(runtime) != T) {
    throw jsi::JSError(runtime, "Object is not a MGLTypedArray");
  }
  return get<T>(runtime);
}

template <MGLTypedArrayKind T>
MGLTypedArray<T> MGLTypedArrayBase::as(jsi::Runtime &runtime) && {
  if (getKind(runtime) != T) {
    throw jsi::JSError(runtime, "Object is not a MGLTypedArray");
  }
  return std::move(*this).get<T>(runtime);
}
