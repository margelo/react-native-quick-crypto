#include <jsi/jsi.h>

namespace fastHMAC {
using namespace facebook;

/// Installs the HMAC C Algorithm in the given jsi::Runtime.
///
/// The function will be injected into the global object under the name "createHmac".
///
/// It's signature is:
/// createHmac(hashAlgorithm: 'sha1' | 'sha256' | 'sha512',
///            key: string): HMAC
void installInRuntime(jsi::Runtime& runtime);
}
