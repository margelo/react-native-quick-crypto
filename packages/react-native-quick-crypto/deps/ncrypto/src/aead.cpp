// ============================================================================
// AEAD (Authenticated Encryption with Associated Data)
#include "ncrypto.h"

#ifdef OPENSSL_IS_BORINGSSL
#include "ncrypto/aead.h"

namespace ncrypto {

const Aead Aead::FromName(std::string_view name) {
  for (const auto& [construct, info] : aeadIndex) {
    if (EqualNoCase(info.name, name)) {
      return Aead(&info, construct());
    }
  }

  return Aead();
}

const Aead Aead::FromCtx(std::string_view name, const AeadCtxPointer& ctx) {
  for (const auto& [_, info] : aeadIndex) {
    if (info.name == name) {
      return Aead(&info, EVP_AEAD_CTX_aead(ctx.get()));
    }
  }

  return Aead();
}

int Aead::getMode() const {
  if (!aead_)
    return -1;

  return info_->mode;
}

std::string_view Aead::getModeLabel() const {
  if (!aead_)
    return {};
  switch (getMode()) {
    case EVP_CIPH_CCM_MODE:
      return "ccm";
    case EVP_CIPH_CTR_MODE:
      return "ctr";
    case EVP_CIPH_GCM_MODE:
      return "gcm";
    case EVP_CIPH_STREAM_CIPHER:
      return "stream";
  }
  return "{unknown}";
}

int Aead::getNonceLength() const {
  if (!aead_)
    return 0;
  return EVP_AEAD_nonce_length(aead_);
}

int Aead::getKeyLength() const {
  if (!aead_)
    return 0;
  return EVP_AEAD_key_length(aead_);
}

int Aead::getMaxOverhead() const {
  if (!aead_)
    return 0;
  return EVP_AEAD_max_overhead(aead_);
}

int Aead::getMaxTagLength() const {
  if (!aead_)
    return 0;
  return EVP_AEAD_max_tag_len(aead_);
}

int Aead::getBlockSize() const {
  if (!aead_)
    return 0;

  // EVP_CIPHER_CTX_block_size returns the block size, in bytes, of the cipher
  // underlying |ctx|, or one if the cipher is a stream cipher.
  return 1;
}

std::string_view Aead::getName() const {
  if (!aead_)
    return "";

  return info_->name;
}

int Aead::getNid() const {
  if (!aead_)
    return 0;

  return info_->nid;
}

const Aead Aead::FromConstructor(Aead::AeadConstructor construct) {
  return Aead(&aeadIndex.at(construct), construct());
}

const std::unordered_map<Aead::AeadConstructor, Aead::AeadInfo> Aead::aeadIndex = {
    {EVP_aead_aes_128_gcm, {.name = LN_aes_128_gcm, .mode = EVP_CIPH_GCM_MODE, .nid = NID_aes_128_gcm}},
    {EVP_aead_aes_192_gcm, {.name = LN_aes_192_gcm, .mode = EVP_CIPH_GCM_MODE, .nid = NID_aes_192_gcm}},
    {EVP_aead_aes_256_gcm, {.name = LN_aes_256_gcm, .mode = EVP_CIPH_GCM_MODE, .nid = NID_aes_256_gcm}},
    {EVP_aead_chacha20_poly1305, {.name = LN_chacha20_poly1305, .mode = EVP_CIPH_STREAM_CIPHER, .nid = NID_chacha20_poly1305}},
    {EVP_aead_xchacha20_poly1305,
     {
         .name = "xchacha20-poly1305",
         .mode = EVP_CIPH_STREAM_CIPHER,
     }},
    {EVP_aead_aes_128_ctr_hmac_sha256,
     {
         .name = "aes-128-ctr-hmac-sha256",
         .mode = EVP_CIPH_CTR_MODE,
     }},
    {EVP_aead_aes_256_ctr_hmac_sha256,
     {
         .name = "aes-256-ctr-hmac-sha256",
         .mode = EVP_CIPH_CTR_MODE,
     }},
    {EVP_aead_aes_128_gcm_siv,
     {
         .name = "aes-128-gcm-siv",
         .mode = EVP_CIPH_GCM_MODE,
     }},
    {EVP_aead_aes_256_gcm_siv,
     {
         .name = "aes-256-gcm-siv",
         .mode = EVP_CIPH_GCM_MODE,
     }},
    {EVP_aead_aes_128_gcm_randnonce,
     {
         .name = "aes-128-gcm-randnonce",
         .mode = EVP_CIPH_GCM_MODE,
     }},
    {EVP_aead_aes_256_gcm_randnonce,
     {
         .name = "aes-256-gcm-randnonce",
         .mode = EVP_CIPH_GCM_MODE,
     }},
    {EVP_aead_aes_128_ccm_bluetooth,
     {
         .name = "aes-128-ccm-bluetooth",
         .mode = EVP_CIPH_CCM_MODE,
     }},
    {EVP_aead_aes_128_ccm_bluetooth_8,
     {
         .name = "aes-128-ccm-bluetooth-8",
         .mode = EVP_CIPH_CCM_MODE,
     }},
    {EVP_aead_aes_128_ccm_matter,
     {
         .name = "aes-128-ccm-matter",
         .mode = EVP_CIPH_CCM_MODE,
     }},
    {EVP_aead_aes_128_eax,
     {.name = "aes-128-eax",
      // BoringSSL does not define a mode constant for EAX. Using STREAM
      // arbitrarily
      .mode = EVP_CIPH_STREAM_CIPHER}},
    {EVP_aead_aes_256_eax,
     {.name = "aes-256-eax",
      // BoringSSL does not define a mode constant for EAX. Using STREAM
      // arbitrarily
      .mode = EVP_CIPH_STREAM_CIPHER}},
};

void Aead::ForEach(AeadNameCallback callback) {
  for (const auto& [_, info] : aeadIndex) {
    callback(info.name);
  }
}

const Aead Aead::EMPTY = Aead();
const Aead Aead::AES_128_GCM = Aead::FromConstructor(EVP_aead_aes_128_gcm);
const Aead Aead::AES_192_GCM = Aead::FromConstructor(EVP_aead_aes_192_gcm);
const Aead Aead::AES_256_GCM = Aead::FromConstructor(EVP_aead_aes_256_gcm);
const Aead Aead::CHACHA20_POLY1305 = Aead::FromConstructor(EVP_aead_chacha20_poly1305);
const Aead Aead::XCHACHA20_POLY1305 = Aead::FromConstructor(EVP_aead_xchacha20_poly1305);
const Aead Aead::AES_128_CTR_HMAC_SHA256 = Aead::FromConstructor(EVP_aead_aes_128_ctr_hmac_sha256);
const Aead Aead::AES_256_CTR_HMAC_SHA256 = Aead::FromConstructor(EVP_aead_aes_256_ctr_hmac_sha256);
const Aead Aead::AES_128_GCM_SIV = Aead::FromConstructor(EVP_aead_aes_128_gcm_siv);
const Aead Aead::AES_256_GCM_SIV = Aead::FromConstructor(EVP_aead_aes_256_gcm_siv);
const Aead Aead::AES_128_GCM_RANDNONCE = Aead::FromConstructor(EVP_aead_aes_128_gcm_randnonce);
const Aead Aead::AES_256_GCM_RANDNONCE = Aead::FromConstructor(EVP_aead_aes_256_gcm_randnonce);
const Aead Aead::AES_128_CCM_BLUETOOTH = Aead::FromConstructor(EVP_aead_aes_128_ccm_bluetooth);
const Aead Aead::AES_128_CCM_BLUETOOTH_8 = Aead::FromConstructor(EVP_aead_aes_128_ccm_bluetooth_8);
const Aead Aead::AES_128_CCM_MATTER = Aead::FromConstructor(EVP_aead_aes_128_ccm_matter);
const Aead Aead::AES_128_EAX = Aead::FromConstructor(EVP_aead_aes_128_eax);
const Aead Aead::AES_256_EAX = Aead::FromConstructor(EVP_aead_aes_256_eax);

AeadCtxPointer AeadCtxPointer::New(const Aead& aead, bool encrypt, const unsigned char* key, size_t keyLen, size_t tagLen) {
  // Note: In the EVP_AEAD API new always calls init
  auto ret = AeadCtxPointer(EVP_AEAD_CTX_new(aead.get(), key, keyLen, tagLen));

  if (!ret) {
    return {};
  }

  return ret;
}

AeadCtxPointer::AeadCtxPointer(EVP_AEAD_CTX* ctx) : ctx_(ctx) {}

AeadCtxPointer::AeadCtxPointer(AeadCtxPointer&& other) noexcept : ctx_(other.release()) {}

AeadCtxPointer& AeadCtxPointer::operator=(AeadCtxPointer&& other) noexcept {
  if (this == &other)
    return *this;
  this->~AeadCtxPointer();
  return *new (this) AeadCtxPointer(std::move(other));
}

AeadCtxPointer::~AeadCtxPointer() {
  reset();
}

void AeadCtxPointer::reset(EVP_AEAD_CTX* ctx) {
  ctx_.reset(ctx);
}

EVP_AEAD_CTX* AeadCtxPointer::release() {
  return ctx_.release();
}

bool AeadCtxPointer::init(const Aead& aead, bool encrypt, const unsigned char* key, size_t keyLen, size_t tagLen) {
  return EVP_AEAD_CTX_init_with_direction(ctx_.get(), aead, key, keyLen, tagLen, encrypt ? evp_aead_seal : evp_aead_open);
}

bool AeadCtxPointer::encrypt(const Buffer<const unsigned char>& in, Buffer<unsigned char>& out, Buffer<unsigned char>& tag,
                             const Buffer<const unsigned char>& nonce, const Buffer<const unsigned char>& aad) {
  if (!ctx_)
    return false;
  return EVP_AEAD_CTX_seal_scatter(ctx_.get(), out.data, tag.data, &tag.len, tag.len, nonce.data, nonce.len, in.data, in.len,
                                   nullptr /* extra_in */, 0 /* extra_in_len */, aad.data, aad.len) == 1;
}

bool AeadCtxPointer::decrypt(const Buffer<const unsigned char>& in, Buffer<unsigned char>& out, const Buffer<const unsigned char>& tag,
                             const Buffer<const unsigned char>& nonce, const Buffer<const unsigned char>& aad) {
  if (!ctx_)
    return false;

  return EVP_AEAD_CTX_open_gather(ctx_.get(), out.data, nonce.data, nonce.len, in.data, in.len, tag.data, tag.len, aad.data, aad.len) == 1;
}
} // namespace ncrypto
#endif
