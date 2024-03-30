//
//  crypto_ec.hpp
//  BEMCheckBox
//
//  Created by Oscar Franco on 30/11/23.
//

#ifndef crypto_ec_h
#define crypto_ec_h

#include <jsi/jsi.h>
#include <openssl/ec.h>
#include <memory>
#include "MGLKeys.h"
#ifdef ANDROID
#include "Utils/MGLUtils.h"
#include "webcrypto/MGLWebCrypto.h"
#else
#include "MGLUtils.h"
#include "MGLWebCrypto.h"
#endif


namespace margelo {
namespace jsi = facebook::jsi;

// There is currently no additional information that the
// ECKeyExport needs to collect, but we need to provide
// the base struct anyway.
struct ECKeyExportConfig final {};

class ECDH final {
 public:
    static ECPointPointer BufferToPoint(jsi::Runtime &rt,
                                        const EC_GROUP* group,
                                        jsi::ArrayBuffer &buf);

    static WebCryptoKeyExportStatus doExport(jsi::Runtime &rt,
                                             std::shared_ptr<KeyObjectData> key_data,
                                             WebCryptoKeyFormat format,
                                             const ECKeyExportConfig &params,
                                             ByteSource* out);
};

WebCryptoKeyExportStatus PKEY_SPKI_Export(KeyObjectData* key_data,
                                          ByteSource* out);

WebCryptoKeyExportStatus EC_Raw_Export(KeyObjectData* key_data,
                                       const ECKeyExportConfig &params,
                                       ByteSource* out);

jsi::Value ExportJWKEcKey(jsi::Runtime &rt,
                          std::shared_ptr<KeyObjectData> key,
                          jsi::Object &target);

std::shared_ptr<KeyObjectData> ImportJWKEcKey(jsi::Runtime &rt,
                                              jsi::Object &jwk,
                                              jsi::Value &namedCurve);

jsi::Value GetEcKeyDetail(jsi::Runtime &rt,
                          std::shared_ptr<KeyObjectData> key);

} // namespace margelo

#endif /* crypto_ec_hpp */
