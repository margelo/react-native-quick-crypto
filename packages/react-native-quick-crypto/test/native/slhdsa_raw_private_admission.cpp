// Standalone regression test. Link with OpenSSL libcrypto; no React Native or
// ncrypto dependency is needed. This tests admission, not provider validation.
// From the package directory (with libcrypto pkg-config configured):
// c++ -std=c++20 test/native/slhdsa_raw_private_admission.cpp $(pkg-config --cflags --libs libcrypto) -o /tmp/rnqc-slh-admission
#include "../../cpp/slhdsa/SlhDsaRawPrivateKeyValidation.hpp"

#include <array>
#include <stdexcept>
#include <string_view>

using margelo::nitro::crypto::SlhDsaRawPrivateKeyBusy;
using margelo::nitro::crypto::SlhDsaRawPrivateKeyValidation;

static void expectBusy(const std::array<uint8_t, 64>& raw) {
  try {
    SlhDsaRawPrivateKeyValidation second("SLH-DSA-SHAKE-128s", raw.data(), raw.size());
  } catch (const SlhDsaRawPrivateKeyBusy& error) {
    if (std::string_view(error.what()) == "SLH-DSA raw private key import busy")
      return;
    throw;
  }
  throw std::runtime_error("Overlapping admission did not reject as busy");
}

int main() {
  const std::array<uint8_t, 64> raw{};
  {
    SlhDsaRawPrivateKeyValidation first("SLH-DSA-SHAKE-128s", raw.data(), raw.size());
    expectBusy(raw);
    try {
      SlhDsaRawPrivateKeyValidation invalid("unsupported", raw.data(), raw.size());
      throw std::logic_error("Invalid variant was admitted");
    } catch (const std::runtime_error& error) {
      if (std::string_view(error.what()) != "SLH-DSA raw private key validation failed")
        throw;
    }
    // A failed constructor must not clear another job's process-wide admission.
    expectBusy(raw);
  }
  {
    SlhDsaRawPrivateKeyValidation readmitted("SLH-DSA-SHAKE-128s", raw.data(), raw.size());
    expectBusy(raw);
  }
  SlhDsaRawPrivateKeyValidation readmittedAgain("SLH-DSA-SHAKE-128s", raw.data(), raw.size());
}
