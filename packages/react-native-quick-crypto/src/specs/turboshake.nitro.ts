import type { HybridObject } from 'react-native-nitro-modules';

export type TurboShakeVariant = 'TurboSHAKE128' | 'TurboSHAKE256';
export type KangarooTwelveVariant = 'KT128' | 'KT256';

export interface TurboShake
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  turboShake(
    variant: TurboShakeVariant,
    domainSeparation: number,
    outputLength: number,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer>;

  kangarooTwelve(
    variant: KangarooTwelveVariant,
    outputLength: number,
    data: ArrayBuffer,
    customization?: ArrayBuffer,
  ): Promise<ArrayBuffer>;
}
