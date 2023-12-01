import type { KWebCryptoKeyFormat } from '../keys';
import type { KeyObjectHandle } from './KeyObjectHandle';

export type ecKeyExport = (
  format: KWebCryptoKeyFormat,
  handle: KeyObjectHandle
) => Promise<any>;
