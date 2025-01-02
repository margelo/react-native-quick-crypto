//
//  TypedArray.cpp
//  react-native-quick-crypto
//
//  Created by Marc Rousavy on 31.10.21.
//  Originally created by Expo (expo-gl)
//

#include "MGLTypedArray.h"

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>
#include <string>
#include <unordered_map>

template <MGLTypedArrayKind T>
using ContentType = typename typedArrayTypeMap<T>::type;

enum class Prop {
  Buffer,             // "buffer"
  Constructor,        // "constructor"
  Name,               // "name"
  Proto,              // "__proto__"
  Length,             // "length"
  ByteLength,         // "byteLength"
  ByteOffset,         // "offset"
  IsView,             // "isView"
  ArrayBuffer,        // "ArrayBuffer"
  Int8Array,          // "Int8Array"
  Int16Array,         // "Int16Array"
  Int32Array,         // "Int32Array"
  Uint8Array,         // "Uint8Array"
  Uint8ClampedArray,  // "Uint8ClampedArray"
  Uint16Array,        // "Uint16Array"
  Uint32Array,        // "Uint32Array"
  Float32Array,       // "Float32Array"
  Float64Array,       // "Float64Array"
};

class PropNameIDCache {
 public:
  const jsi::PropNameID &get(jsi::Runtime &runtime, Prop prop) {
    auto key = reinterpret_cast<uintptr_t>(&runtime);
    if (this->props.find(key) == this->props.end()) {
      this->props[key] = std::unordered_map<Prop, std::unique_ptr<jsi::PropNameID>>();
    }
    if (!this->props[key][prop]) {
      this->props[key][prop] = std::make_unique<jsi::PropNameID>(createProp(runtime, prop));
    }
    return *(this->props[key][prop]);
  }

  const jsi::PropNameID &getConstructorNameProp(jsi::Runtime &runtime, MGLTypedArrayKind kind);

  void invalidate(uintptr_t key) {
    if (props.find(key) != props.end()) {
      props[key].clear();
    }
  }
 private:
  std::unordered_map<uintptr_t, std::unordered_map<Prop, std::unique_ptr<jsi::PropNameID>>> props;

  jsi::PropNameID createProp(jsi::Runtime &runtime, Prop prop);
};

PropNameIDCache propNameIDCache;

InvalidateCacheOnDestroy::InvalidateCacheOnDestroy(jsi::Runtime &runtime) {
  key = reinterpret_cast<uintptr_t>(&runtime);
}
InvalidateCacheOnDestroy::~InvalidateCacheOnDestroy() {
  propNameIDCache.invalidate(key);
}

MGLTypedArrayKind getTypedArrayKindForName(const std::string &name);

MGLTypedArrayBase::MGLTypedArrayBase(jsi::Runtime &runtime, size_t size,
                                     MGLTypedArrayKind kind)
    : MGLTypedArrayBase(
          runtime,
          runtime.global()
              .getProperty(
                runtime,
                propNameIDCache.getConstructorNameProp(runtime, kind))
              .asObject(runtime)
              .asFunction(runtime)
              .callAsConstructor(runtime, {static_cast<double>(size)})
              .asObject(runtime)) {}

MGLTypedArrayBase::MGLTypedArrayBase(jsi::Runtime &runtime,
                                     const jsi::Object &obj)
    : jsi::Object(jsi::Value(runtime, obj).asObject(runtime)) {}

MGLTypedArrayKind MGLTypedArrayBase::getKind(jsi::Runtime &runtime) const {
  auto constructorName =
      this->getProperty(runtime,
                        propNameIDCache.get(runtime, Prop::Constructor))
          .asObject(runtime)
          .getProperty(runtime, propNameIDCache.get(runtime, Prop::Name))
          .asString(runtime)
          .utf8(runtime);
  return getTypedArrayKindForName(constructorName);
}

size_t MGLTypedArrayBase::size(jsi::Runtime &runtime) const {
  return getProperty(runtime, propNameIDCache.get(runtime, Prop::Length))
      .asNumber();
}

size_t MGLTypedArrayBase::length(jsi::Runtime &runtime) const {
  return getProperty(runtime, propNameIDCache.get(runtime, Prop::Length))
      .asNumber();
}

size_t MGLTypedArrayBase::byteLength(jsi::Runtime &runtime) const {
  return getProperty(runtime, propNameIDCache.get(runtime, Prop::ByteLength))
      .asNumber();
}

size_t MGLTypedArrayBase::byteOffset(jsi::Runtime &runtime) const {
  return getProperty(runtime, propNameIDCache.get(runtime, Prop::ByteOffset))
      .asNumber();
}

bool MGLTypedArrayBase::hasBuffer(jsi::Runtime &runtime) const {
  auto buffer =
      getProperty(runtime, propNameIDCache.get(runtime, Prop::Buffer));
  return buffer.isObject() && buffer.asObject(runtime).isArrayBuffer(runtime);
}

std::vector<uint8_t> MGLTypedArrayBase::toVector(jsi::Runtime &runtime) {
  auto start = reinterpret_cast<uint8_t *>(getBuffer(runtime).data(runtime) +
                                           byteOffset(runtime));
  auto end = start + byteLength(runtime);
  return std::vector<uint8_t>(start, end);
}

jsi::ArrayBuffer MGLTypedArrayBase::getBuffer(jsi::Runtime &runtime) const {
  auto buffer =
      getProperty(runtime, propNameIDCache.get(runtime, Prop::Buffer));
  if (buffer.isObject() && buffer.asObject(runtime).isArrayBuffer(runtime)) {
    return buffer.asObject(runtime).getArrayBuffer(runtime);
  } else {
    throw std::runtime_error("no ArrayBuffer attached");
  }
}

bool isTypedArray(jsi::Runtime &runtime, const jsi::Object &jsObj) {
  auto jsVal =
      runtime.global()
          .getProperty(runtime, propNameIDCache.get(runtime, Prop::ArrayBuffer))
          .asObject(runtime)
          .getProperty(runtime, propNameIDCache.get(runtime, Prop::IsView))
          .asObject(runtime)
          .asFunction(runtime)
          .callWithThis(runtime, runtime.global(),
                        {jsi::Value(runtime, jsObj)});
  if (jsVal.isBool()) {
    return jsVal.getBool();
  } else {
    throw std::runtime_error("value is not a boolean");
  }
}

MGLTypedArrayBase getTypedArray(jsi::Runtime &runtime,
                                const jsi::Object &jsObj) {
  auto jsVal =
      runtime.global()
          .getProperty(runtime, propNameIDCache.get(runtime, Prop::ArrayBuffer))
          .asObject(runtime)
          .getProperty(runtime, propNameIDCache.get(runtime, Prop::IsView))
          .asObject(runtime)
          .asFunction(runtime)
          .callWithThis(runtime, runtime.global(),
                        {jsi::Value(runtime, jsObj)});
  if (jsVal.isBool()) {
    return MGLTypedArrayBase(runtime, jsObj);
  } else {
    throw std::runtime_error("value is not a boolean");
  }
}

std::vector<uint8_t> arrayBufferToVector(jsi::Runtime &runtime,
                                         jsi::Object &jsObj) {
  if (!jsObj.isArrayBuffer(runtime)) {
    throw std::runtime_error("Object is not an ArrayBuffer");
  }
  auto jsArrayBuffer = jsObj.getArrayBuffer(runtime);

  uint8_t *dataBlock = jsArrayBuffer.data(runtime);
  size_t blockSize =
      jsArrayBuffer
          .getProperty(runtime, propNameIDCache.get(runtime, Prop::ByteLength))
          .asNumber();
  return std::vector<uint8_t>(dataBlock, dataBlock + blockSize);
}

void arrayBufferUpdate(jsi::Runtime &runtime, jsi::ArrayBuffer &buffer,
                       std::vector<uint8_t> data, size_t offset) {
  uint8_t *dataBlock = buffer.data(runtime);
  size_t blockSize = buffer.size(runtime);
  if (data.size() > blockSize) {
    throw jsi::JSError(runtime, "ArrayBuffer is to small to fit data");
  }
  std::copy(data.begin(), data.end(), dataBlock + offset);
}

template <MGLTypedArrayKind T>
MGLTypedArray<T>::MGLTypedArray(jsi::Runtime &runtime, size_t size)
    : MGLTypedArrayBase(runtime, size, T) {}

template <MGLTypedArrayKind T>
MGLTypedArray<T>::MGLTypedArray(jsi::Runtime &runtime,
                                std::vector<ContentType<T>> data)
    : MGLTypedArrayBase(runtime, data.size(), T) {
  update(runtime, data);
}

template <MGLTypedArrayKind T>
MGLTypedArray<T>::MGLTypedArray(MGLTypedArrayBase &&base)
    : MGLTypedArrayBase(std::move(base)) {}

template <MGLTypedArrayKind T>
std::vector<ContentType<T>> MGLTypedArray<T>::toVector(jsi::Runtime &runtime) {
  auto start = reinterpret_cast<ContentType<T> *>(
      getBuffer(runtime).data(runtime) + byteOffset(runtime));
  auto end = start + size(runtime);
  return std::vector<ContentType<T>>(start, end);
}

template <MGLTypedArrayKind T>
void MGLTypedArray<T>::update(jsi::Runtime &runtime,
                              const std::vector<ContentType<T>> &data) {
  if (data.size() != size(runtime)) {
    throw jsi::JSError(
        runtime,
        "TypedArray can only be updated with a vector of the same size");
  }
  uint8_t *rawData = getBuffer(runtime).data(runtime) + byteOffset(runtime);
  std::copy(data.begin(), data.end(),
            reinterpret_cast<ContentType<T> *>(rawData));
}

template <MGLTypedArrayKind T>
void MGLTypedArray<T>::updateUnsafe(jsi::Runtime &runtime, ContentType<T> *data, size_t length) {
    if (length != size(runtime)) {
    throw jsi::JSError(runtime, "TypedArray can only be updated with an array of the same size");
  }
  uint8_t *rawData = getBuffer(runtime).data(runtime) + byteOffset(runtime);
  memcpy(rawData, data, length);
}

template <MGLTypedArrayKind T>
uint8_t* MGLTypedArray<T>::data(jsi::Runtime &runtime) {
  return getBuffer(runtime).data(runtime) + byteOffset(runtime);
}

const jsi::PropNameID &PropNameIDCache::getConstructorNameProp(
    jsi::Runtime &runtime, MGLTypedArrayKind kind) {
  switch (kind) {
    case MGLTypedArrayKind::Int8Array:
      return get(runtime, Prop::Int8Array);
    case MGLTypedArrayKind::Int16Array:
      return get(runtime, Prop::Int16Array);
    case MGLTypedArrayKind::Int32Array:
      return get(runtime, Prop::Int32Array);
    case MGLTypedArrayKind::Uint8Array:
      return get(runtime, Prop::Uint8Array);
    case MGLTypedArrayKind::Uint8ClampedArray:
      return get(runtime, Prop::Uint8ClampedArray);
    case MGLTypedArrayKind::Uint16Array:
      return get(runtime, Prop::Uint16Array);
    case MGLTypedArrayKind::Uint32Array:
      return get(runtime, Prop::Uint32Array);
    case MGLTypedArrayKind::Float32Array:
      return get(runtime, Prop::Float32Array);
    case MGLTypedArrayKind::Float64Array:
      return get(runtime, Prop::Float64Array);
  }
}

jsi::PropNameID PropNameIDCache::createProp(jsi::Runtime &runtime, Prop prop) {
  auto create = [&](const std::string &propName) {
    return jsi::PropNameID::forUtf8(runtime, propName);
  };
  switch (prop) {
    case Prop::Buffer:
      return create("buffer");
    case Prop::Constructor:
      return create("constructor");
    case Prop::Name:
      return create("name");
    case Prop::Proto:
      return create("__proto__");
    case Prop::Length:
      return create("length");
    case Prop::ByteLength:
      return create("byteLength");
    case Prop::ByteOffset:
      return create("byteOffset");
    case Prop::IsView:
      return create("isView");
    case Prop::ArrayBuffer:
      return create("ArrayBuffer");
    case Prop::Int8Array:
      return create("Int8Array");
    case Prop::Int16Array:
      return create("Int16Array");
    case Prop::Int32Array:
      return create("Int32Array");
    case Prop::Uint8Array:
      return create("Uint8Array");
    case Prop::Uint8ClampedArray:
      return create("Uint8ClampedArray");
    case Prop::Uint16Array:
      return create("Uint16Array");
    case Prop::Uint32Array:
      return create("Uint32Array");
    case Prop::Float32Array:
      return create("Float32Array");
    case Prop::Float64Array:
      return create("Float64Array");
  }
}

std::unordered_map<std::string, MGLTypedArrayKind> nameToKindMap = {
    {"Int8Array", MGLTypedArrayKind::Int8Array},
    {"Int16Array", MGLTypedArrayKind::Int16Array},
    {"Int32Array", MGLTypedArrayKind::Int32Array},
    {"Uint8Array", MGLTypedArrayKind::Uint8Array},
    {"Uint8ClampedArray", MGLTypedArrayKind::Uint8ClampedArray},
    {"Uint16Array", MGLTypedArrayKind::Uint16Array},
    {"Uint32Array", MGLTypedArrayKind::Uint32Array},
    {"Float32Array", MGLTypedArrayKind::Float32Array},
    {"Float64Array", MGLTypedArrayKind::Float64Array},
};

MGLTypedArrayKind getTypedArrayKindForName(const std::string &name) {
  return nameToKindMap.at(name);
}

template class MGLTypedArray<MGLTypedArrayKind::Int8Array>;
template class MGLTypedArray<MGLTypedArrayKind::Int16Array>;
template class MGLTypedArray<MGLTypedArrayKind::Int32Array>;
template class MGLTypedArray<MGLTypedArrayKind::Uint8Array>;
template class MGLTypedArray<MGLTypedArrayKind::Uint8ClampedArray>;
template class MGLTypedArray<MGLTypedArrayKind::Uint16Array>;
template class MGLTypedArray<MGLTypedArrayKind::Uint32Array>;
template class MGLTypedArray<MGLTypedArrayKind::Float32Array>;
template class MGLTypedArray<MGLTypedArrayKind::Float64Array>;
