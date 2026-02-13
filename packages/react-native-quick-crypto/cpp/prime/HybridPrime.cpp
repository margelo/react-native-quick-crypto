#include "HybridPrime.hpp"
#include "QuickCryptoUtils.hpp"
#include <ncrypto.h>

namespace margelo::nitro::crypto {

using namespace ncrypto;

static BignumPointer toBignum(
    const std::optional<std::shared_ptr<ArrayBuffer>>& buf) {
  if (!buf.has_value() || buf.value()->size() == 0) {
    return BignumPointer();
  }
  return BignumPointer(buf.value()->data(), buf.value()->size());
}

static std::shared_ptr<ArrayBuffer> generatePrimeImpl(
    double size, bool safe,
    const std::optional<std::shared_ptr<ArrayBuffer>>& add,
    const std::optional<std::shared_ptr<ArrayBuffer>>& rem) {
  int bits = static_cast<int>(size);

  auto addBn = toBignum(add);
  auto remBn = toBignum(rem);

  BignumPointer::PrimeConfig config{bits, safe, addBn, remBn};
  auto prime = BignumPointer::NewPrime(config);
  if (!prime) {
    throw std::runtime_error("Failed to generate prime");
  }

  auto encoded = prime.encode();
  if (!encoded) {
    throw std::runtime_error("Failed to encode prime");
  }

  return ToNativeArrayBuffer(encoded.get<uint8_t>(), encoded.size());
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>>
HybridPrime::generatePrime(
    double size, bool safe,
    const std::optional<std::shared_ptr<ArrayBuffer>>& add,
    const std::optional<std::shared_ptr<ArrayBuffer>>& rem) {
  auto addCopy = add.has_value() ? std::make_optional(ToNativeArrayBuffer(add.value())) : std::nullopt;
  auto remCopy = rem.has_value() ? std::make_optional(ToNativeArrayBuffer(rem.value())) : std::nullopt;

  return Promise<std::shared_ptr<ArrayBuffer>>::async(
      [size, safe,
       addCopy = std::move(addCopy),
       remCopy = std::move(remCopy)]() {
        return generatePrimeImpl(size, safe, addCopy, remCopy);
      });
}

std::shared_ptr<ArrayBuffer> HybridPrime::generatePrimeSync(
    double size, bool safe,
    const std::optional<std::shared_ptr<ArrayBuffer>>& add,
    const std::optional<std::shared_ptr<ArrayBuffer>>& rem) {
  return generatePrimeImpl(size, safe, add, rem);
}

bool HybridPrime::checkPrimeSync(
    const std::shared_ptr<ArrayBuffer>& candidate, double checks) {
  BignumPointer bn(candidate->data(), candidate->size());
  if (!bn) {
    throw std::runtime_error("Invalid candidate");
  }

  int result = bn.isPrime(static_cast<int>(checks));
  if (result == -1) {
    throw std::runtime_error("Prime check failed");
  }
  return result == 1;
}

std::shared_ptr<Promise<bool>> HybridPrime::checkPrime(
    const std::shared_ptr<ArrayBuffer>& candidate, double checks) {
  auto candidateCopy = ToNativeArrayBuffer(candidate);
  return Promise<bool>::async([candidateCopy, checks]() {
    BignumPointer bn(candidateCopy->data(), candidateCopy->size());
    if (!bn) {
      throw std::runtime_error("Invalid candidate");
    }
    int result = bn.isPrime(static_cast<int>(checks));
    if (result == -1) {
      throw std::runtime_error("Prime check failed");
    }
    return result == 1;
  });
}

} // namespace margelo::nitro::crypto
