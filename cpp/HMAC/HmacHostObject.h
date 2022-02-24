//
//  HmacHostObject.h
//  PinkPanda
//
//  Created by Marc Rousavy on 22.02.22.
//

#ifndef HmacHostObject_h
#define HmacHostObject_h

#include <jsi/jsi.h>
#include <string>
#include <openssl/hmac.h>

namespace fastHMAC {

using namespace facebook;

class HmacHostObject : public jsi::HostObject {

public:
explicit HmacHostObject(const std::string& hashAlgorithm, const std::string& key);
~HmacHostObject();

public:
jsi::Value get(jsi::Runtime&, const jsi::PropNameID& name) override;
std::vector<jsi::PropNameID> getPropertyNames(jsi::Runtime& rt) override;

private:
HMAC_CTX* context;

};

}

#endif /* HmacHostObject_h */
