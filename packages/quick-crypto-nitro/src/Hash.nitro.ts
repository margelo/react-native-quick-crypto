import { Android, iOS, type HybridObject } from 'nitro-core';

export * from '#nitro/Hash';

@Android({
  language: 'c++',
  implementation: {
    className: 'HybridHash',
    include: '<QuickCryptoNitro/HybridHash.hpp>',
  },
})
@iOS({
  language: 'c++',
  implementation: {
    className: 'HybridHash',
    include: '<QuickCryptoNitro/HybridHash.hpp>',
  },
})
export declare class Hash extends HybridObject {
  public constructor(algorithm: string);
  update(data: ArrayBuffer): void;
  digest(): ArrayBuffer;
}
