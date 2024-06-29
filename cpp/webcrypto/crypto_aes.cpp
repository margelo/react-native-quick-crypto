#include "crypto_aes.h"

#ifdef ANDROID
#include "JSIUtils/MGLJSIUtils.h"
#include "Utils/MGLUtils.h"
#else
#include "MGLJSIUtils.h"
#include "MGLUtils.h"
#endif

namespace margelo {

namespace {
// Implements general AES encryption and decryption for CBC
// The key_data must be a secret key.
// On success, this function sets out to a new ByteSource
// instance containing the results and returns WebCryptoCipherStatus::OK.
WebCryptoCipherStatus AES_Cipher(const AESCipherConfig& params, ByteSource* out) {
  CHECK_NOT_NULL(params.key);
  CHECK_EQ(params.key->GetKeyType(), kKeyTypeSecret);

  const int mode = EVP_CIPHER_mode(params.cipher);

  CipherCtxPointer ctx(EVP_CIPHER_CTX_new());
  EVP_CIPHER_CTX_init(ctx.get());
  if (mode == EVP_CIPH_WRAP_MODE)
    EVP_CIPHER_CTX_set_flags(ctx.get(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

  const bool encrypt = params.mode == AESCipherConfig::Mode::kEncrypt;

  if (!EVP_CipherInit_ex(
          ctx.get(),
          params.cipher,
          nullptr,
          nullptr,
          nullptr,
          encrypt)) {
    // Cipher init failed
    return WebCryptoCipherStatus::FAILED;
  }

  if (mode == EVP_CIPH_GCM_MODE && !EVP_CIPHER_CTX_ctrl(
        ctx.get(),
        EVP_CTRL_AEAD_SET_IVLEN,
        params.iv.size(),
        nullptr)) {
    return WebCryptoCipherStatus::FAILED;
  }

  if (!EVP_CIPHER_CTX_set_key_length(
          ctx.get(),
          params.key->GetSymmetricKeySize()) ||
      !EVP_CipherInit_ex(
          ctx.get(),
          nullptr,
          nullptr,
          reinterpret_cast<const unsigned char*>(params.key->GetSymmetricKey().c_str()),
          params.iv.data<unsigned char>(),
          encrypt)) {
    return WebCryptoCipherStatus::FAILED;
  }

  size_t tag_len = 0;

  if (mode == EVP_CIPH_GCM_MODE) {
    switch (params.mode) {
      case AESCipherConfig::Mode::kDecrypt:
        // If in decrypt mode, the auth tag must be set in the params.tag.
        CHECK(params.tag);
        if (!EVP_CIPHER_CTX_ctrl(ctx.get(),
                                 EVP_CTRL_AEAD_SET_TAG,
                                 params.tag.size(),
                                 const_cast<char*>(params.tag.data<char>()))) {
          return WebCryptoCipherStatus::FAILED;
        }
        break;
      case AESCipherConfig::Mode::kEncrypt:
        // In decrypt mode, we grab the tag length here. We'll use it to
        // ensure that that allocated buffer has enough room for both the
        // final block and the auth tag. Unlike our other AES-GCM implementation
        // in CipherBase, in WebCrypto, the auth tag is concatenated to the end
        // of the generated ciphertext and returned in the same ArrayBuffer.
        tag_len = params.length;
        break;
      default:
        throw std::runtime_error("Unreachable code in AES_Cipher");
    }
  }

  size_t total = 0;
  int buf_len = params.data.size() + EVP_CIPHER_CTX_block_size(ctx.get()) + tag_len;
  int out_len;

  if (mode == EVP_CIPH_GCM_MODE &&
      params.additional_data.size() &&
      !EVP_CipherUpdate(
            ctx.get(),
            nullptr,
            &out_len,
            params.additional_data.data<unsigned char>(),
            params.additional_data.size())) {
    return WebCryptoCipherStatus::FAILED;
  }

  ByteSource::Builder buf(buf_len);

  // In some outdated version of OpenSSL (e.g.
  // ubi81_sharedlibs_openssl111fips_x64) may be used in sharedlib mode, the
  // logic will be failed when input size is zero. The newly OpenSSL has fixed
  // it up. But we still have to regard zero as special in Node.js code to
  // prevent old OpenSSL failure.
  //
  // Refs: https://github.com/openssl/openssl/commit/420cb707b880e4fb649094241371701013eeb15f
  // Refs: https://github.com/nodejs/node/pull/38913#issuecomment-866505244
  if (params.data.size() == 0) {
    out_len = 0;
  } else if (!EVP_CipherUpdate(ctx.get(),
                               buf.data<unsigned char>(),
                               &out_len,
                               params.data.data<unsigned char>(),
                               params.data.size())) {
    return WebCryptoCipherStatus::FAILED;
  }

  total += out_len;
  CHECK_LE(out_len, buf_len);
  out_len = EVP_CIPHER_CTX_block_size(ctx.get());
  if (!EVP_CipherFinal_ex(
          ctx.get(), buf.data<unsigned char>() + total, &out_len)) {
    return WebCryptoCipherStatus::FAILED;
  }
  total += out_len;

  // If using AES_GCM, grab the generated auth tag and append
  // it to the end of the ciphertext.
  if (params.mode == AESCipherConfig::Mode::kEncrypt && mode == EVP_CIPH_GCM_MODE) {
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(),
                             EVP_CTRL_AEAD_GET_TAG,
                             tag_len,
                             buf.data<unsigned char>() + total))
      return WebCryptoCipherStatus::FAILED;
    total += tag_len;
  }

  // It's possible that we haven't used the full allocated space. Size down.
  *out = std::move(buf).release(total);

  return WebCryptoCipherStatus::OK;
}

// The AES_CTR implementation here takes it's inspiration from the chromium
// implementation here:
// https://github.com/chromium/chromium/blob/7af6cfd/components/webcrypto/algorithms/aes_ctr.cc

template <typename T>
T CeilDiv(T a, T b) {
  return a == 0 ? 0 : 1 + (a - 1) / b;
}

BignumPointer GetCounter(const AESCipherConfig& params) {
  unsigned int remainder = (params.length % CHAR_BIT);
  const unsigned char* data = params.iv.data<unsigned char>();

  if (remainder == 0) {
    unsigned int byte_length = params.length / CHAR_BIT;
    return BignumPointer(BN_bin2bn(
        data + params.iv.size() - byte_length,
        byte_length,
        nullptr));
  }

  unsigned int byte_length =
      CeilDiv(params.length, static_cast<size_t>(CHAR_BIT));

  std::vector<unsigned char> counter(
      data + params.iv.size() - byte_length,
      data + params.iv.size());
  counter[0] &= ~(0xFF << remainder);

  return BignumPointer(BN_bin2bn(counter.data(), counter.size(), nullptr));
}

std::vector<unsigned char> BlockWithZeroedCounter(
    const AESCipherConfig& params) {
  unsigned int length_bytes = params.length / CHAR_BIT;
  unsigned int remainder = params.length % CHAR_BIT;

  const unsigned char* data = params.iv.data<unsigned char>();

  std::vector<unsigned char> new_counter_block(data, data + params.iv.size());

  size_t index = new_counter_block.size() - length_bytes;
  memset(&new_counter_block.front() + index, 0, length_bytes);

  if (remainder)
    new_counter_block[index - 1] &= 0xFF << remainder;

  return new_counter_block;
}

WebCryptoCipherStatus AES_CTR_Cipher2(
    const AESCipherConfig& params,
    const ByteSource &in,
    unsigned const char* counter,
    unsigned char* out) {
  CipherCtxPointer ctx(EVP_CIPHER_CTX_new());
  const bool encrypt = params.mode == AESCipherConfig::Mode::kEncrypt;

  if (!EVP_CipherInit_ex(
          ctx.get(),
          params.cipher,
          nullptr,
          reinterpret_cast<const unsigned char*>(params.key->GetSymmetricKey().c_str()),
          counter,
          encrypt)) {
    // Cipher init failed
    return WebCryptoCipherStatus::FAILED;
  }

  int out_len = 0;
  int final_len = 0;
  if (!EVP_CipherUpdate(
          ctx.get(),
          out,
          &out_len,
          params.data.data<unsigned char>(),
          params.data.size())) {
    return WebCryptoCipherStatus::FAILED;
  }

  if (!EVP_CipherFinal_ex(ctx.get(), out + out_len, &final_len))
    return WebCryptoCipherStatus::FAILED;

  out_len += final_len;
  if (static_cast<unsigned>(out_len) != params.data.size())
    return WebCryptoCipherStatus::FAILED;

  return WebCryptoCipherStatus::OK;
}

WebCryptoCipherStatus AES_CTR_Cipher(
    const AESCipherConfig& params,
    ByteSource* out) {
  BignumPointer num_counters(BN_new());
  if (!BN_lshift(num_counters.get(), BN_value_one(), params.length))
    return WebCryptoCipherStatus::FAILED;

  BignumPointer current_counter = GetCounter(params);

  BignumPointer num_output(BN_new());

  if (!BN_set_word(num_output.get(), CeilDiv(params.data.size(), kAesBlockSize)))
    return WebCryptoCipherStatus::FAILED;

  // Just like in chromium's implementation, if the counter will
  // be incremented more than there are counter values, we fail.
  if (BN_cmp(num_output.get(), num_counters.get()) > 0)
    return WebCryptoCipherStatus::FAILED;

  BignumPointer remaining_until_reset(BN_new());
  if (!BN_sub(remaining_until_reset.get(),
              num_counters.get(),
              current_counter.get())) {
    return WebCryptoCipherStatus::FAILED;
  }

  // Output size is identical to the input size.
  ByteSource::Builder buf(params.data.size());

  // Also just like in chromium's implementation, if we can process
  // the input without wrapping the counter, we'll do it as a single
  // call here. If we can't, we'll fallback to the a two-step approach
  if (BN_cmp(remaining_until_reset.get(), num_output.get()) >= 0) {
    auto status = AES_CTR_Cipher2(params,
                                  params.data,
                                  params.iv.data<unsigned char>(),
                                  buf.data<unsigned char>());
    if (status == WebCryptoCipherStatus::OK) *out = std::move(buf).release();
    return status;
  }

  BN_ULONG blocks_part1 = BN_get_word(remaining_until_reset.get());
  BN_ULONG input_size_part1 = blocks_part1 * kAesBlockSize;

  // Encrypt the first part...
  auto status =
      AES_CTR_Cipher2(params,
                      ByteSource::Foreign(params.data.data<char>(), input_size_part1),
                      params.iv.data<unsigned char>(),
                      buf.data<unsigned char>());

  if (status != WebCryptoCipherStatus::OK)
    return status;

  // Wrap the counter around to zero
  std::vector<unsigned char> new_counter_block = BlockWithZeroedCounter(params);

  // Encrypt the second part...
  status =
      AES_CTR_Cipher2(params,
                      ByteSource::Foreign(params.data.data<char>() + input_size_part1,
                                          params.data.size() - input_size_part1),
                      new_counter_block.data(),
                      buf.data<unsigned char>() + input_size_part1);

  if (status == WebCryptoCipherStatus::OK) *out = std::move(buf).release();

  return status;
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

bool ValidateIV(
    jsi::Runtime &rt,
    const jsi::Value &value,
    AESCipherConfig *params) {
  params->iv = GetByteSourceFromJS(rt, value, "iv");
  return true;
}

bool ValidateCounter(
  jsi::Runtime &rt,
  const jsi::Value &value,
  AESCipherConfig* params) {
  CHECK(CheckIsUint32(value));  // Length
  params->length = (uint32_t)value.asNumber();
  if (params->iv.size() != 16 ||
      params->length == 0 ||
      params->length > 128) {
    throw std::runtime_error("Invalid counter (AES)");
    return false;
  }
  return true;
}

bool ValidateAuthTag(
    jsi::Runtime &rt,
    AESCipherConfig::Mode cipher_mode,
    const jsi::Value &value_len,
    const jsi::Value &value_auth_tag,
    AESCipherConfig *params) {
  switch (cipher_mode) {
    case AESCipherConfig::Mode::kDecrypt: {
      ByteSource tag = GetByteSourceFromJS(rt, value_auth_tag, "auth_tag");
      params->tag = std::move(tag);
      break;
    }
    case AESCipherConfig::Mode::kEncrypt: {
      CHECK(CheckIsUint32(value_len)); // Length
      params->length = (uint32_t)value_len.asNumber();
      if (params->length > 128) {
        throw std::runtime_error("Invalid tag length (AES)");
        return false;
      }
      break;
    }
    default:
      throw std::runtime_error("Unreachable code in ValidateAuthTag (AES)");
  }
  return true;
}

bool ValidateAdditionalData(
    jsi::Runtime &rt,
    const jsi::Value &value,
    AESCipherConfig *params) {
  // Additional Data
  params->additional_data = GetByteSourceFromJS(rt, value, "additional_data");
  return true;
}

void UseDefaultIV(AESCipherConfig* params) {
  params->iv = ByteSource::Foreign(kDefaultWrapIV, strlen(kDefaultWrapIV));
}

}  // namespace

AESCipherConfig AESCipher::GetParamsFromJS(jsi::Runtime &rt,
                                          const jsi::Value *args) {
  AESCipherConfig params;
  unsigned int offset = 0;

  // mode (encrypt/decrypt)
  AESCipherConfig::Mode mode =
    static_cast<AESCipherConfig::Mode>(args[offset].getNumber());
  params.mode = mode;
  offset++;

  // key (handle)
  if (!args[offset].isObject()) {
    throw std::runtime_error("arg is not a KeyObjectHandle: key");
  }
  std::shared_ptr<KeyObjectHandle> handle =
    std::static_pointer_cast<KeyObjectHandle>(
      args[offset].asObject(rt).getHostObject(rt));
  params.key = handle->Data();
  offset++;

  // data
  params.data = GetByteSourceFromJS(rt, args[offset], "data");
  offset++;

  // AES Key Variant
  if (CheckIsInt32(args[offset])) {
    params.variant = static_cast<AESKeyVariant>(args[offset].asNumber());
  }
  // offset++; // The below variant-dependent params advance offset themselves

  // cipher
  int cipher_nid;

  switch (params.variant) {
    case kKeyVariantAES_CTR_128:
      if (!ValidateIV(rt, args[offset + 1], &params) ||
          !ValidateCounter(rt, args[offset + 2], &params)) {
        return params;
      }
      cipher_nid = NID_aes_128_ctr;
      break;
    case kKeyVariantAES_CTR_192:
      if (!ValidateIV(rt, args[offset + 1], &params) ||
          !ValidateCounter(rt, args[offset + 2], &params)) {
        return params;
      }
      cipher_nid = NID_aes_192_ctr;
      break;
    case kKeyVariantAES_CTR_256:
      if (!ValidateIV(rt, args[offset + 1], &params) ||
          !ValidateCounter(rt, args[offset + 2], &params)) {
        return params;
      }
      cipher_nid = NID_aes_256_ctr;
      break;
    case kKeyVariantAES_CBC_128:
      if (!ValidateIV(rt, args[offset + 1], &params))
        return params;
      cipher_nid = NID_aes_128_cbc;
      break;
    case kKeyVariantAES_CBC_192:
      if (!ValidateIV(rt, args[offset + 1], &params))
        return params;
      cipher_nid = NID_aes_192_cbc;
      break;
    case kKeyVariantAES_CBC_256:
      if (!ValidateIV(rt, args[offset + 1], &params))
        return params;
      cipher_nid = NID_aes_256_cbc;
      break;
    case kKeyVariantAES_KW_128:
      UseDefaultIV(&params);
      cipher_nid = NID_id_aes128_wrap;
      break;
    case kKeyVariantAES_KW_192:
      UseDefaultIV(&params);
      cipher_nid = NID_id_aes192_wrap;
      break;
    case kKeyVariantAES_KW_256:
      UseDefaultIV(&params);
      cipher_nid = NID_id_aes256_wrap;
      break;
    case kKeyVariantAES_GCM_128:
      if (!ValidateIV(rt, args[offset + 1], &params) ||
          !ValidateAuthTag(rt, mode, args[offset + 2], args[offset + 3], &params) ||
          !ValidateAdditionalData(rt, args[offset + 4], &params)) {
        return params;
      }
      cipher_nid = NID_aes_128_gcm;
      break;
    case kKeyVariantAES_GCM_192:
      if (!ValidateIV(rt, args[offset + 1], &params) ||
          !ValidateAuthTag(rt, mode, args[offset + 2], args[offset + 3], &params) ||
          !ValidateAdditionalData(rt, args[offset + 4], &params)) {
        return params;
      }
      cipher_nid = NID_aes_192_gcm;
      break;
    case kKeyVariantAES_GCM_256:
      if (!ValidateIV(rt, args[offset + 1], &params) ||
          !ValidateAuthTag(rt, mode, args[offset + 2], args[offset + 3], &params) ||
          !ValidateAdditionalData(rt, args[offset + 4], &params)) {
        return params;
      }
      cipher_nid = NID_aes_256_gcm;
      break;
    default:
      throw std::runtime_error("Unreachable code in GetParamsFromJS (AES)");
  }

  params.cipher = EVP_get_cipherbynid(cipher_nid);
  if (params.cipher == nullptr) {
    throw std::runtime_error("Unknown cipher (AES)");
    return params;
  }

  if (params.iv.size() <
      static_cast<size_t>(EVP_CIPHER_iv_length(params.cipher))) {
    throw std::runtime_error("Invalid IV length (AES)");
    return params;
  }

  return params;
}

WebCryptoCipherStatus AESCipher::DoCipher(const AESCipherConfig &params,
                                          ByteSource *out) {
  // TODO: threading / async here, as we don't have jsi::Runtime
#define V(name, fn)                                                           \
  case kKeyVariantAES_ ## name:                                               \
    return fn(params, out);
  switch (params.variant) {
    VARIANTS(V)
    default:
      throw std::runtime_error("Unreachable code in DoCipher (AES)");
  }
#undef V
}

} // namespace margelo
