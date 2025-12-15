import { describe, it, expect, mock } from "bun:test";
import crypto from "crypto";

mock.module("react-native-quick-crypto", () => {
    return {
        default: { ...crypto, install: () => { } },
        ...crypto,
        install: () => { },
    };
});
mock.module("react-native", () => ({}));

describe('BIP39 Error Handling', async () => {
    const { generateMnemonic, entropyToMnemonic, InvalidEntropyError } = await import('../src/index');

    it('throws InvalidEntropyError for invalid strength', () => {
        expect(() => generateMnemonic(129)).toThrow(InvalidEntropyError);
        expect(() => generateMnemonic(129)).toThrow("Strength must be divisible by 32");
    });

    it('throws InvalidEntropyError for invalid entropy buffer size', () => {
        expect(() => entropyToMnemonic(Buffer.alloc(10))).toThrow(InvalidEntropyError);
    });
});
