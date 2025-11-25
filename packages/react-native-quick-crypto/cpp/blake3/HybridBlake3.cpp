#include "HybridBlake3.hpp"

#include <NitroModules/ArrayBuffer.hpp>
#include <cstring>
#include <stdexcept>

#include "Utils.hpp"

namespace margelo::nitro::crypto {

void HybridBlake3::initHash() {
  blake3_hasher_init(&hasher);
  mode = Mode::Hash;
  key = std::nullopt;
  context = std::nullopt;
  initialized = true;
}

void HybridBlake3::initKeyed(const std::shared_ptr<ArrayBuffer>& keyBuffer) {
  if (!keyBuffer || keyBuffer->size() != BLAKE3_KEY_LEN) {
    throw std::runtime_error("BLAKE3 key must be exactly 32 bytes");
  }

  std::array<uint8_t, BLAKE3_KEY_LEN> keyArray;
  std::memcpy(keyArray.data(), keyBuffer->data(), BLAKE3_KEY_LEN);

  blake3_hasher_init_keyed(&hasher, keyArray.data());
  mode = Mode::Keyed;
  key = keyArray;
  context = std::nullopt;
  initialized = true;
}

void HybridBlake3::initDeriveKey(const std::string& ctx) {
  if (ctx.empty()) {
    throw std::runtime_error("BLAKE3 context must be a non-empty string");
  }

  blake3_hasher_init_derive_key(&hasher, ctx.c_str());
  mode = Mode::DeriveKey;
  key = std::nullopt;
  context = ctx;
  initialized = true;
}

void HybridBlake3::update(const std::shared_ptr<ArrayBuffer>& data) {
  if (!initialized) {
    throw std::runtime_error("BLAKE3 hasher not initialized");
  }
  if (!data) {
    return;
  }
  blake3_hasher_update(&hasher, data->data(), data->size());
}

std::shared_ptr<ArrayBuffer> HybridBlake3::digest(std::optional<double> length) {
  if (!initialized) {
    throw std::runtime_error("BLAKE3 hasher not initialized");
  }

  size_t outLen = BLAKE3_OUT_LEN;
  if (length.has_value()) {
    double len = length.value();
    if (len <= 0 || len > 65535) {
      throw std::runtime_error("BLAKE3 output length must be between 1 and 65535");
    }
    outLen = static_cast<size_t>(len);
  }

  auto output = new uint8_t[outLen];
  blake3_hasher_finalize(&hasher, output, outLen);

  return std::make_shared<margelo::nitro::NativeArrayBuffer>(output, outLen, [=]() { delete[] output; });
}

void HybridBlake3::reset() {
  if (!initialized) {
    throw std::runtime_error("BLAKE3 hasher not initialized");
  }

  switch (mode) {
    case Mode::Hash:
      blake3_hasher_init(&hasher);
      break;
    case Mode::Keyed:
      if (key.has_value()) {
        blake3_hasher_init_keyed(&hasher, key->data());
      }
      break;
    case Mode::DeriveKey:
      if (context.has_value()) {
        blake3_hasher_init_derive_key(&hasher, context->c_str());
      }
      break;
  }
}

std::shared_ptr<HybridBlake3Spec> HybridBlake3::copy() {
  if (!initialized) {
    throw std::runtime_error("BLAKE3 hasher not initialized");
  }

  auto copied = std::make_shared<HybridBlake3>();

  std::memcpy(&copied->hasher, &hasher, sizeof(blake3_hasher));
  copied->initialized = true;
  copied->mode = mode;
  copied->key = key;
  copied->context = context;

  return copied;
}

std::string HybridBlake3::getVersion() {
  return std::string(blake3_version());
}

} // namespace margelo::nitro::crypto
