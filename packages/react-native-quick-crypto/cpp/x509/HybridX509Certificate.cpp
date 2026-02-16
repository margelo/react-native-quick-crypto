#include "HybridX509Certificate.hpp"
#include "../keys/HybridKeyObjectHandle.hpp"
#include "../keys/KeyObjectData.hpp"
#include "QuickCryptoUtils.hpp"
#include <ncrypto.h>

namespace margelo::nitro::crypto {

std::string HybridX509Certificate::bioToString(ncrypto::BIOPointer bio) const {
  if (!bio)
    return "";
  BUF_MEM* mem = bio;
  if (!mem || mem->length == 0)
    return "";
  return std::string(mem->data, mem->length);
}

void HybridX509Certificate::init(const std::shared_ptr<ArrayBuffer>& buffer) {
  ncrypto::Buffer<const unsigned char> buf{.data = reinterpret_cast<const unsigned char*>(buffer->data()), .len = buffer->size()};
  auto result = ncrypto::X509Pointer::Parse(buf);
  if (!result) {
    throw std::runtime_error("Failed to parse X509 certificate");
  }
  cert_ = std::move(result.value);
}

std::string HybridX509Certificate::subject() {
  return bioToString(cert_.view().getSubject());
}

std::string HybridX509Certificate::subjectAltName() {
  return bioToString(cert_.view().getSubjectAltName());
}

std::string HybridX509Certificate::issuer() {
  return bioToString(cert_.view().getIssuer());
}

std::string HybridX509Certificate::infoAccess() {
  return bioToString(cert_.view().getInfoAccess());
}

std::string HybridX509Certificate::validFrom() {
  return bioToString(cert_.view().getValidFrom());
}

std::string HybridX509Certificate::validTo() {
  return bioToString(cert_.view().getValidTo());
}

double HybridX509Certificate::validFromDate() {
  return static_cast<double>(cert_.view().getValidFromTime()) * 1000.0;
}

double HybridX509Certificate::validToDate() {
  return static_cast<double>(cert_.view().getValidToTime()) * 1000.0;
}

std::string HybridX509Certificate::signatureAlgorithm() {
  auto algo = cert_.view().getSignatureAlgorithm();
  if (!algo.has_value())
    return "";
  return std::string(algo.value());
}

std::string HybridX509Certificate::signatureAlgorithmOid() {
  return cert_.view().getSignatureAlgorithmOID().value_or("");
}

std::string HybridX509Certificate::serialNumber() {
  auto serial = cert_.view().getSerialNumber();
  if (!serial)
    return "";
  return std::string(static_cast<const char*>(serial.get()), serial.size());
}

std::string HybridX509Certificate::fingerprint() {
  return cert_.view().getFingerprint(ncrypto::Digest::SHA1).value_or("");
}

std::string HybridX509Certificate::fingerprint256() {
  return cert_.view().getFingerprint(ncrypto::Digest::SHA256).value_or("");
}

std::string HybridX509Certificate::fingerprint512() {
  return cert_.view().getFingerprint(ncrypto::Digest::SHA512).value_or("");
}

std::shared_ptr<ArrayBuffer> HybridX509Certificate::raw() {
  auto bio = cert_.view().toDER();
  if (!bio) {
    throw std::runtime_error("Failed to export certificate as DER");
  }
  BUF_MEM* mem = bio;
  return ToNativeArrayBuffer(reinterpret_cast<const uint8_t*>(mem->data), mem->length);
}

std::string HybridX509Certificate::pem() {
  return bioToString(cert_.view().toPEM());
}

std::shared_ptr<HybridKeyObjectHandleSpec> HybridX509Certificate::publicKey() {
  auto result = cert_.view().getPublicKey();
  if (!result) {
    throw std::runtime_error("Failed to extract public key from certificate");
  }
  auto handle = std::make_shared<HybridKeyObjectHandle>();
  handle->setKeyObjectData(KeyObjectData::CreateAsymmetric(KeyType::PUBLIC, std::move(result.value)));
  return handle;
}

std::vector<std::string> HybridX509Certificate::keyUsage() {
  std::vector<std::string> usages;
  cert_.view().enumUsages([&](const char* usage) { usages.emplace_back(usage); });
  return usages;
}

bool HybridX509Certificate::ca() {
  return cert_.view().isCA();
}

bool HybridX509Certificate::checkIssued(const std::shared_ptr<HybridX509CertificateHandleSpec>& other) {
  auto otherCert = std::dynamic_pointer_cast<HybridX509Certificate>(other);
  if (!otherCert) {
    throw std::runtime_error("Invalid X509Certificate");
  }
  return cert_.view().isIssuedBy(otherCert->cert_.view());
}

bool HybridX509Certificate::checkPrivateKey(const std::shared_ptr<HybridKeyObjectHandleSpec>& key) {
  auto handle = std::dynamic_pointer_cast<HybridKeyObjectHandle>(key);
  if (!handle) {
    throw std::runtime_error("Invalid key object");
  }
  return cert_.view().checkPrivateKey(handle->getKeyObjectData().GetAsymmetricKey());
}

bool HybridX509Certificate::verify(const std::shared_ptr<HybridKeyObjectHandleSpec>& key) {
  auto handle = std::dynamic_pointer_cast<HybridKeyObjectHandle>(key);
  if (!handle) {
    throw std::runtime_error("Invalid key object");
  }
  return cert_.view().checkPublicKey(handle->getKeyObjectData().GetAsymmetricKey());
}

std::optional<std::string> HybridX509Certificate::checkHost(const std::string& name, double flags) {
  ncrypto::DataPointer peername;
  auto match = cert_.view().checkHost(name, static_cast<int>(flags), &peername);
  if (match == ncrypto::X509View::CheckMatch::MATCH) {
    if (peername) {
      return std::string(static_cast<const char*>(peername.get()), peername.size());
    }
    return name;
  }
  return std::nullopt;
}

std::optional<std::string> HybridX509Certificate::checkEmail(const std::string& email, double flags) {
  auto match = cert_.view().checkEmail(email, static_cast<int>(flags));
  if (match == ncrypto::X509View::CheckMatch::MATCH) {
    return email;
  }
  return std::nullopt;
}

std::optional<std::string> HybridX509Certificate::checkIP(const std::string& ip) {
  auto match = cert_.view().checkIp(ip, 0);
  if (match == ncrypto::X509View::CheckMatch::MATCH) {
    return ip;
  }
  return std::nullopt;
}

} // namespace margelo::nitro::crypto
