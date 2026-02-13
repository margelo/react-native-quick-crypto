import { NitroModules } from 'react-native-nitro-modules';
import { Buffer } from '@craftzdog/react-native-buffer';
import type { Certificate as NativeCertificate } from './specs/certificate.nitro';
import type { BinaryLike } from './utils';
import { binaryLikeToArrayBuffer } from './utils';

let native: NativeCertificate;
function getNative(): NativeCertificate {
  if (native == null) {
    native = NitroModules.createHybridObject<NativeCertificate>('Certificate');
  }
  return native;
}

function toArrayBuffer(
  spkac: BinaryLike,
  encoding?: BufferEncoding,
): ArrayBuffer {
  if (typeof spkac === 'string') {
    return binaryLikeToArrayBuffer(spkac, encoding || 'utf8');
  }
  return binaryLikeToArrayBuffer(spkac);
}

export class Certificate {
  static exportChallenge(spkac: BinaryLike, encoding?: BufferEncoding): Buffer {
    return Buffer.from(
      getNative().exportChallenge(toArrayBuffer(spkac, encoding)),
    );
  }

  static exportPublicKey(spkac: BinaryLike, encoding?: BufferEncoding): Buffer {
    return Buffer.from(
      getNative().exportPublicKey(toArrayBuffer(spkac, encoding)),
    );
  }

  static verifySpkac(spkac: BinaryLike, encoding?: BufferEncoding): boolean {
    return getNative().verifySpkac(toArrayBuffer(spkac, encoding));
  }
}
