import type { HybridObject } from 'react-native-nitro-modules';

export interface TurboShake
  extends HybridObject<{ ios: 'c++'; android: 'c++' }> {
  turboShake(
    variant: string,
    domainSeparation: number,
    outputLength: number,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer>;

  kangarooTwelve(
    variant: string,
    outputLength: number,
    data: ArrayBuffer,
    customization?: ArrayBuffer,
  ): Promise<ArrayBuffer>;
}
