#include <NitroModules/ArrayBuffer.hpp>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "HybridTurboShake.hpp"
#include "QuickCryptoUtils.hpp"

// TurboSHAKE128/256 and KangarooTwelve KT128/256 (RFC 9861).
// Implementation adapted from Node.js src/crypto/crypto_turboshake.cc
// (commit e0cab9dcf75), which itself adapts the OpenSSL keccak1600.c
// reference variant. OpenSSL does not yet expose these algorithms via EVP,
// so the Keccak-p[1600, n_r=12] permutation and sponge are provided here.

namespace margelo::nitro::crypto {

namespace {

  // ---------------------------------------------------------------------------
  // Keccak-p[1600, n_r=12] permutation (FIPS 202 §3.3-3.4, RFC 9861 §2.2).
  // ---------------------------------------------------------------------------

  inline uint64_t ROL64(uint64_t val, int offset) {
    if (offset == 0)
      return val;
    return (val << offset) | (val >> (64 - offset));
  }

  inline uint64_t LoadLE64(const uint8_t* src) {
    return static_cast<uint64_t>(src[0]) | (static_cast<uint64_t>(src[1]) << 8) | (static_cast<uint64_t>(src[2]) << 16) |
           (static_cast<uint64_t>(src[3]) << 24) | (static_cast<uint64_t>(src[4]) << 32) | (static_cast<uint64_t>(src[5]) << 40) |
           (static_cast<uint64_t>(src[6]) << 48) | (static_cast<uint64_t>(src[7]) << 56);
  }

  inline void StoreLE64(uint8_t* dst, uint64_t val) {
    dst[0] = static_cast<uint8_t>(val);
    dst[1] = static_cast<uint8_t>(val >> 8);
    dst[2] = static_cast<uint8_t>(val >> 16);
    dst[3] = static_cast<uint8_t>(val >> 24);
    dst[4] = static_cast<uint8_t>(val >> 32);
    dst[5] = static_cast<uint8_t>(val >> 40);
    dst[6] = static_cast<uint8_t>(val >> 48);
    dst[7] = static_cast<uint8_t>(val >> 56);
  }

  constexpr unsigned char kRhoTates[5][5] = {
      {0, 1, 62, 28, 27}, {36, 44, 6, 55, 20}, {3, 10, 43, 25, 39}, {41, 45, 15, 21, 8}, {18, 2, 61, 56, 14},
  };

  // Round constants for Keccak-f[1600]; TurboSHAKE uses indices 12..23.
  constexpr uint64_t kIotas[24] = {
      0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL, 0x000000000000808bULL,
      0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL, 0x0000000000000088ULL,
      0x0000000080008009ULL, 0x000000008000000aULL, 0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
      0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
      0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
  };

  void KeccakP1600_12(uint64_t A[5][5]) {
    for (size_t round = 12; round < 24; round++) {
      uint64_t C[5];
      for (size_t x = 0; x < 5; x++) {
        C[x] = A[0][x] ^ A[1][x] ^ A[2][x] ^ A[3][x] ^ A[4][x];
      }
      uint64_t D[5];
      for (size_t x = 0; x < 5; x++) {
        D[x] = C[(x + 4) % 5] ^ ROL64(C[(x + 1) % 5], 1);
      }
      for (size_t y = 0; y < 5; y++) {
        for (size_t x = 0; x < 5; x++) {
          A[y][x] ^= D[x];
        }
      }
      for (size_t y = 0; y < 5; y++) {
        for (size_t x = 0; x < 5; x++) {
          A[y][x] = ROL64(A[y][x], kRhoTates[y][x]);
        }
      }
      uint64_t T[5][5];
      memcpy(T, A, sizeof(T));
      for (size_t y = 0; y < 5; y++) {
        for (size_t x = 0; x < 5; x++) {
          A[y][x] = T[x][(3 * y + x) % 5];
        }
      }
      for (size_t y = 0; y < 5; y++) {
        uint64_t row[5];
        for (size_t x = 0; x < 5; x++) {
          row[x] = A[y][x] ^ (~A[y][(x + 1) % 5] & A[y][(x + 2) % 5]);
        }
        memcpy(A[y], row, sizeof(row));
      }
      A[0][0] ^= kIotas[round];
    }
  }

  // ---------------------------------------------------------------------------
  // TurboSHAKE sponge (RFC 9861 §2.2, App. A.2/A.3).
  // TurboSHAKE128: rate = 168 bytes (capacity 256 bits).
  // TurboSHAKE256: rate = 136 bytes (capacity 512 bits).
  // ---------------------------------------------------------------------------

  constexpr size_t kTurboSHAKE128Rate = 168;
  constexpr size_t kTurboSHAKE256Rate = 136;

  void TurboSHAKE(const uint8_t* input, size_t input_len, size_t rate, uint8_t domain_sep, uint8_t* output, size_t output_len) {
    uint64_t A[5][5] = {};
    size_t lane_count = rate / 8;

    size_t offset = 0;
    while (offset + rate <= input_len) {
      for (size_t i = 0; i < lane_count; i++) {
        A[i / 5][i % 5] ^= LoadLE64(input + offset + i * 8);
      }
      KeccakP1600_12(A);
      offset += rate;
    }

    size_t remaining = input_len - offset;
    // Sized for the larger TurboSHAKE128 rate (168); also fits the 136-byte TurboSHAKE256 rate.
    uint8_t pad[kTurboSHAKE128Rate] = {};
    if (remaining > 0) {
      memcpy(pad, input + offset, remaining);
    }
    pad[remaining] ^= domain_sep;
    pad[rate - 1] ^= 0x80;

    for (size_t i = 0; i < lane_count; i++) {
      A[i / 5][i % 5] ^= LoadLE64(pad + i * 8);
    }
    KeccakP1600_12(A);

    size_t out_offset = 0;
    while (out_offset < output_len) {
      size_t block = output_len - out_offset;
      if (block > rate)
        block = rate;
      size_t full_lanes = block / 8;
      for (size_t i = 0; i < full_lanes; i++) {
        StoreLE64(output + out_offset + i * 8, A[i / 5][i % 5]);
      }
      size_t rem = block % 8;
      if (rem > 0) {
        uint8_t tmp[8];
        StoreLE64(tmp, A[full_lanes / 5][full_lanes % 5]);
        memcpy(output + out_offset + full_lanes * 8, tmp, rem);
      }
      out_offset += block;
      if (out_offset < output_len) {
        KeccakP1600_12(A);
      }
    }
  }

  void TurboSHAKE128(const uint8_t* input, size_t input_len, uint8_t domain_sep, uint8_t* output, size_t output_len) {
    TurboSHAKE(input, input_len, kTurboSHAKE128Rate, domain_sep, output, output_len);
  }

  void TurboSHAKE256(const uint8_t* input, size_t input_len, uint8_t domain_sep, uint8_t* output, size_t output_len) {
    TurboSHAKE(input, input_len, kTurboSHAKE256Rate, domain_sep, output, output_len);
  }

  // ---------------------------------------------------------------------------
  // KangarooTwelve tree hashing (RFC 9861 §3).
  // ---------------------------------------------------------------------------

  constexpr size_t kChunkSize = 8192;

  // length_encode(x) per RFC 9861 §3.3.
  std::vector<uint8_t> LengthEncode(size_t x) {
    if (x == 0) {
      return {0x00};
    }
    std::vector<uint8_t> result;
    size_t val = x;
    while (val > 0) {
      result.push_back(static_cast<uint8_t>(val & 0xFF));
      val >>= 8;
    }
    size_t n = result.size();
    for (size_t i = 0; i < n / 2; i++) {
      std::swap(result[i], result[n - 1 - i]);
    }
    result.push_back(static_cast<uint8_t>(n));
    return result;
  }

  using TurboSHAKEFn = void (*)(const uint8_t* input, size_t input_len, uint8_t domain_sep, uint8_t* output, size_t output_len);

  void KangarooTwelve(const uint8_t* message, size_t msg_len, const uint8_t* customization, size_t custom_len, uint8_t* output,
                      size_t output_len, TurboSHAKEFn turboshake, size_t cv_len) {
    auto len_enc = LengthEncode(custom_len);
    size_t s_len = msg_len + custom_len + len_enc.size();

    // Short message: |S| <= 8192.
    if (s_len <= kChunkSize) {
      std::vector<uint8_t> s(s_len);
      size_t pos = 0;
      if (msg_len > 0) {
        memcpy(s.data() + pos, message, msg_len);
        pos += msg_len;
      }
      if (custom_len > 0) {
        memcpy(s.data() + pos, customization, custom_len);
        pos += custom_len;
      }
      memcpy(s.data() + pos, len_enc.data(), len_enc.size());

      turboshake(s.data(), s_len, 0x07, output, output_len);
      return;
    }

    // S is virtual: M || C || length_encode(|C|). Read on demand.
    auto read_s = [&](size_t s_offset, uint8_t* buf, size_t len) {
      size_t copied = 0;
      if (s_offset < msg_len && copied < len) {
        size_t avail = msg_len - s_offset;
        size_t to_copy = avail < (len - copied) ? avail : (len - copied);
        memcpy(buf + copied, message + s_offset, to_copy);
        copied += to_copy;
        s_offset += to_copy;
      }
      size_t custom_start = msg_len;
      if (s_offset < custom_start + custom_len && copied < len) {
        size_t off_in_custom = s_offset - custom_start;
        size_t avail = custom_len - off_in_custom;
        size_t to_copy = avail < (len - copied) ? avail : (len - copied);
        memcpy(buf + copied, customization + off_in_custom, to_copy);
        copied += to_copy;
        s_offset += to_copy;
      }
      size_t le_start = msg_len + custom_len;
      if (s_offset < le_start + len_enc.size() && copied < len) {
        size_t off_in_le = s_offset - le_start;
        size_t avail = len_enc.size() - off_in_le;
        size_t to_copy = avail < (len - copied) ? avail : (len - copied);
        memcpy(buf + copied, len_enc.data() + off_in_le, to_copy);
        copied += to_copy;
      }
    };

    std::vector<uint8_t> first_chunk(kChunkSize);
    read_s(0, first_chunk.data(), kChunkSize);

    std::vector<uint8_t> final_node;
    final_node.reserve(kChunkSize + 8 + ((s_len / kChunkSize) * cv_len) + 16);
    final_node.insert(final_node.end(), first_chunk.begin(), first_chunk.end());
    final_node.push_back(0x03);
    final_node.insert(final_node.end(), 7, 0x00);

    size_t offset = kChunkSize;
    size_t num_blocks = 0;
    std::vector<uint8_t> chunk(kChunkSize);
    std::vector<uint8_t> cv(cv_len);

    while (offset < s_len) {
      size_t block_size = s_len - offset;
      if (block_size > kChunkSize)
        block_size = kChunkSize;

      chunk.resize(block_size);
      read_s(offset, chunk.data(), block_size);

      turboshake(chunk.data(), block_size, 0x0B, cv.data(), cv_len);
      final_node.insert(final_node.end(), cv.begin(), cv.end());
      num_blocks++;
      offset += block_size;
    }

    auto num_blocks_enc = LengthEncode(num_blocks);
    final_node.insert(final_node.end(), num_blocks_enc.begin(), num_blocks_enc.end());
    final_node.push_back(0xFF);
    final_node.push_back(0xFF);

    turboshake(final_node.data(), final_node.size(), 0x06, output, output_len);
  }

  void KT128(const uint8_t* message, size_t msg_len, const uint8_t* customization, size_t custom_len, uint8_t* output, size_t output_len) {
    KangarooTwelve(message, msg_len, customization, custom_len, output, output_len, TurboSHAKE128, 32);
  }

  void KT256(const uint8_t* message, size_t msg_len, const uint8_t* customization, size_t custom_len, uint8_t* output, size_t output_len) {
    KangarooTwelve(message, msg_len, customization, custom_len, output, output_len, TurboSHAKE256, 64);
  }

  uint8_t parseDomainSeparation(double value) {
    if (!(value >= 0x01 && value <= 0x7F) || value != static_cast<double>(static_cast<uint8_t>(value))) {
      throw std::runtime_error("TurboSHAKE domainSeparation must be an integer in 0x01..0x7F");
    }
    return static_cast<uint8_t>(value);
  }

  uint32_t parseOutputLength(double value) {
    if (!(value > 0)) {
      throw std::runtime_error("outputLength must be > 0");
    }
    // 16 MiB upper bound matches HybridHash::setParams to keep memory bounded.
    constexpr double kMaxOutputBytes = 16.0 * 1024.0 * 1024.0;
    if (value > kMaxOutputBytes) {
      throw std::runtime_error("outputLength exceeds maximum allowed size");
    }
    if (value != static_cast<double>(static_cast<uint32_t>(value))) {
      throw std::runtime_error("outputLength must be an integer");
    }
    return static_cast<uint32_t>(value);
  }

} // namespace

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>> HybridTurboShake::turboShake(TurboShakeVariant variant, double domainSeparation,
                                                                                    double outputLength,
                                                                                    const std::shared_ptr<ArrayBuffer>& data) {
  uint8_t ds = parseDomainSeparation(domainSeparation);
  uint32_t outLen = parseOutputLength(outputLength);

  bool is128 = variant == TurboShakeVariant::TURBOSHAKE128;

  auto nativeData = ToNativeArrayBuffer(data);

  return Promise<std::shared_ptr<ArrayBuffer>>::async([is128, ds, outLen, nativeData]() -> std::shared_ptr<ArrayBuffer> {
    auto outBuf = std::make_unique<uint8_t[]>(outLen);
    const uint8_t* in = reinterpret_cast<const uint8_t*>(nativeData->data());
    size_t inLen = nativeData->size();
    if (is128) {
      TurboSHAKE128(in, inLen, ds, outBuf.get(), outLen);
    } else {
      TurboSHAKE256(in, inLen, ds, outBuf.get(), outLen);
    }
    uint8_t* raw = outBuf.get();
    return std::make_shared<NativeArrayBuffer>(outBuf.release(), outLen, [raw]() { delete[] raw; });
  });
}

std::shared_ptr<Promise<std::shared_ptr<ArrayBuffer>>>
HybridTurboShake::kangarooTwelve(KangarooTwelveVariant variant, double outputLength, const std::shared_ptr<ArrayBuffer>& data,
                                 const std::optional<std::shared_ptr<ArrayBuffer>>& customization) {
  uint32_t outLen = parseOutputLength(outputLength);

  bool is128 = variant == KangarooTwelveVariant::KT128;

  auto nativeData = ToNativeArrayBuffer(data);
  std::optional<std::shared_ptr<ArrayBuffer>> nativeCustom;
  if (customization.has_value()) {
    nativeCustom = ToNativeArrayBuffer(customization.value());
  }

  return Promise<std::shared_ptr<ArrayBuffer>>::async(
      [is128, outLen, nativeData, nativeCustom = std::move(nativeCustom)]() -> std::shared_ptr<ArrayBuffer> {
        const uint8_t* in = reinterpret_cast<const uint8_t*>(nativeData->data());
        size_t inLen = nativeData->size();
        const uint8_t* custom = nullptr;
        size_t customLen = 0;
        if (nativeCustom.has_value() && nativeCustom.value()->size() > 0) {
          custom = reinterpret_cast<const uint8_t*>(nativeCustom.value()->data());
          customLen = nativeCustom.value()->size();
        }

        // Mirror Node's overflow guard for s_len = msg + custom + length_encode(|custom|).
        // length_encode produces at most sizeof(size_t) + 1 bytes.
        constexpr size_t kMaxLengthEncodeSize = sizeof(size_t) + 1;
        if (inLen > SIZE_MAX - customLen || inLen + customLen > SIZE_MAX - kMaxLengthEncodeSize) {
          throw std::runtime_error("KangarooTwelve input length overflow");
        }

        auto outBuf = std::make_unique<uint8_t[]>(outLen);
        if (is128) {
          KT128(in, inLen, custom, customLen, outBuf.get(), outLen);
        } else {
          KT256(in, inLen, custom, customLen, outBuf.get(), outLen);
        }
        uint8_t* raw = outBuf.get();
        return std::make_shared<NativeArrayBuffer>(outBuf.release(), outLen, [raw]() { delete[] raw; });
      });
}

} // namespace margelo::nitro::crypto
