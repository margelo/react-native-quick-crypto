import { describe, it, expect, mock } from "bun:test";
import crypto from "crypto";

// Mock RNQC
mock.module("react-native-quick-crypto", () => {
    return {
        default: { ...crypto, install: () => { } },
        ...crypto,
        install: () => { },
    };
});
mock.module("react-native", () => ({}));

describe('BIP39 Multi-Language Support', async () => {
    const { generateMnemonic, validateMnemonic } = await import('../src/index');
    const { wordlists } = await import('../src/wordlists');

    it('generates a mnemonic in Spanish', () => {
        const mnemonic = generateMnemonic(128, wordlists.spanish);
        const words = mnemonic.split(' ');
        expect(words.length).toBe(12);
        expect(validateMnemonic(mnemonic, wordlists.spanish)).toBe(true);
        expect(validateMnemonic(mnemonic, wordlists.english)).toBe(false); // Should fail validation in English
    });

    it('generates a mnemonic in Japanese', () => {
        const mnemonic = generateMnemonic(128, wordlists.japanese);
        expect(typeof mnemonic).toBe('string');

        // Japanese uses \u3000 (Ideographic Space) as delimiter
        expect(mnemonic.includes('\u3000')).toBe(true);
        expect(mnemonic.includes(' ')).toBe(false);

        const words = mnemonic.split('\u3000');
        expect(words.length).toBe(12);
        expect(validateMnemonic(mnemonic, wordlists.japanese)).toBe(true);
    });

    it('generates a mnemonic in Chinese Simplified', () => {
        const mnemonic = generateMnemonic(128, wordlists.chinese_simplified);
        expect(validateMnemonic(mnemonic, wordlists.chinese_simplified)).toBe(true);
    });
});
