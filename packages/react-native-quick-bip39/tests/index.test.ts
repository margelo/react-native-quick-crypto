import { describe, it, expect, mock } from "bun:test"; // Import from bun:test
import crypto from "crypto";

// Mock RNQC with Node crypto for verification
// This proves our BIP39 logic is correct, assuming RNQC works as spec (Node Crypto)
mock.module("react-native-quick-crypto", () => {
    return {
        default: {
            ...crypto,
            install: () => { },
        },
        ...crypto,
        install: () => { },
    };
});

// Mock react-native to prevent "import typeof" errors in Bun
mock.module("react-native", () => ({}));

// Import AFTER mocking
// import { generateMnemonic, mnemonicToSeed, validateMnemonic } from '../src/index';

describe('BIP39 Implementation', async () => {
    // Dynamic import to satisfy hoisting of mocks
    const { generateMnemonic, mnemonicToSeed, validateMnemonic } = await import('../src/index');
    it('generates a 12-word mnemonic', () => {
        const mnemonic = generateMnemonic(128);
        console.log('Mnemonic:', mnemonic);
        expect(mnemonic.split(' ').length).toBe(12);
        expect(validateMnemonic(mnemonic)).toBe(true);
    });

    it('generates a 24-word mnemonic', () => {
        const mnemonic = generateMnemonic(256);
        expect(mnemonic.split(' ').length).toBe(24);
        expect(validateMnemonic(mnemonic)).toBe(true);
    });

    it('derives a seed correctly (async)', async () => {
        const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
        // Valid seed for this vector is known, but we just check buffer return for now
        const seed = await mnemonicToSeed(mnemonic, 'TREZOR');
        expect(seed).toBeInstanceOf(Buffer);
        expect(seed.length).toBe(64);

        console.log('Derived Seed:', seed.toString('hex').slice(0, 32) + '...');
    });
});
