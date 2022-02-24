#include <jsi/jsi.h>

namespace fastpbkdf2 {
using namespace facebook;

/// Installs the fastpbkdf2 C Algorithm in the given jsi::Runtime.
///
/// The function will be injected into the global object under the name "pbkdf2".
///
/// It's signature is:
/// fastkbdf2(password: BytesLike,
///           salt: BytesLike,
///           iterations: number,
///           keyLength: number,
///           hashAlgorithm: 'sha1' | 'sha256' | 'sha512'): Uint8Array
void installInRuntime(jsi::Runtime& runtime);
}
