import { pbkdf2, pbkdf2Sync, randomBytes, createHash } from 'react-native-quick-crypto';
import { wordlist as english } from './wordlists/english';
import { BIP39Error, InvalidEntropyError, InvalidMnemonicError, InvalidChecksumError } from './errors';

export * from './errors';

function normalize(str: string): string {
    return str.normalize('NFKD');
}

function bytesToBinary(bytes: Buffer): string {
    return Array.from(bytes)
        .map((x) => x.toString(2).padStart(8, '0'))
        .join('');
}

function deriveChecksumBits(entropyBuffer: Buffer): string {
    const ENT = entropyBuffer.length * 8;
    const CS = ENT / 32;
    const hash = createHash('SHA-256').update(entropyBuffer).digest();
    return bytesToBinary(Buffer.from(hash) as unknown as Buffer).slice(0, CS);
}

/**
 * Generates a random mnemonic using the specified strength and wordlist.
 *
 * @param strength - Entropy bits (default: 128). Must be a multiple of 32 (e.g., 128, 256).
 * @param wordlist - Array of 2048 words (default: English). Import others from `react-native-quick-bip39/wordlists/*`.
 * @returns Space-separated mnemonic string.
 * @throws {InvalidEntropyError} If strength is not divisible by 32.
 */
export function generateMnemonic(strength: number = 128, wordlist: readonly string[] = english): string {
    if (strength % 32 !== 0) throw new InvalidEntropyError('Strength must be divisible by 32');
    const buffer = randomBytes(strength / 8);

    return entropyToMnemonic(buffer as unknown as Buffer, wordlist);
}

/**
 * Converts raw entropy bytes to a mnemonic phrase.
 *
 * @param entropy - Buffer containing entropy bytes (16-32 bytes).
 * @param wordlist - Array of 2048 words (default: English).
 * @returns Space-separated mnemonic string.
 * @throws {InvalidEntropyError} If entropy length is invalid.
 */
export function entropyToMnemonic(entropy: Buffer, wordlist: readonly string[] = english): string {
    if (entropy.length < 16 || entropy.length > 32 || entropy.length % 4 !== 0) {
        throw new InvalidEntropyError('Invalid entropy');
    }

    const entropyBits = bytesToBinary(entropy);
    const checksumBits = deriveChecksumBits(entropy);
    const bits = entropyBits + checksumBits;
    const chunks = bits.match(/(.{1,11})/g);

    if (!chunks) {
        throw new BIP39Error('Failed to generate mnemonic: invalid entropy processing');
    }

    const words = chunks.map((binary) => {
        const index = parseInt(binary, 2);
        return wordlist[index];
    });

    const firstWord = wordlist[0] ?? '';
    const delimiter = /[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff66-\uff9f]/.test(firstWord) ? '\u3000' : ' ';
    return words.join(delimiter);
}

/**
 * Converts a mnemonic phrase to a seed buffer asynchronously.
 * Uses `react-native-quick-crypto`'s efficient native thread pool.
 *
 * @param mnemonic - The mnemonic phrase.
 * @param password - Optional passphrase (default: empty string).
 * @returns Promise resolving to the seed buffer (64 bytes).
 * @throws {BIP39Error} If key derivation fails.
 */
export function mnemonicToSeed(mnemonic: string, password: string = ''): Promise<Buffer> {
    const mnemonicNorm = normalize(mnemonic);
    const saltNorm = normalize('mnemonic' + password);

    return new Promise((resolve, reject) => {
        // This is the heavy lifting - runs on native thread via RNQC
        pbkdf2(mnemonicNorm, saltNorm, 2048, 64, 'SHA-512', (err, derivedKey) => {
            if (err) return reject(new BIP39Error(err.message));
            if (!derivedKey) return reject(new BIP39Error('Failed to derive key'));
            resolve(derivedKey as unknown as Buffer);
        });
    });
}

/**
 * Converts a mnemonic phrase to a seed buffer synchronously.
 * Blocking operation - use with caution on UI threads.
 *
 * @param mnemonic - The mnemonic phrase.
 * @param password - Optional passphrase (default: empty string).
 * @returns The seed buffer (64 bytes).
 */
export function mnemonicToSeedSync(mnemonic: string, password: string = ''): Buffer {
    const mnemonicNorm = normalize(mnemonic);
    const saltNorm = normalize('mnemonic' + password);
    // Sync version usually blocks UI, but RNQC's implementation is super fast C++
    return pbkdf2Sync(mnemonicNorm, saltNorm, 2048, 64, 'SHA-512') as unknown as Buffer;
}

/**
 * Validates a mnemonic phrase against a wordlist.
 * Checks word validity, count, and checksum.
 *
 * @param mnemonic - The mnemonic phrase to validate.
 * @param wordlist - Array of 2048 words (default: English).
 * @returns `true` if valid, `false` otherwise.
 */
export function validateMnemonic(mnemonic: string, wordlist: readonly string[] = english): boolean {
    try {
        const words = normalize(mnemonic).split(' ');
        if (words.length % 3 !== 0) return false;

        if (!words.every(w => wordlist.includes(w))) return false;

        const bits = words.map(word => {
            const index = wordlist.indexOf(word);
            if (index === -1) throw new InvalidMnemonicError(`Invalid word found: ${word}`);
            return index.toString(2).padStart(11, '0');
        }).join('');

        const ENT = (words.length * 11) - (words.length / 3);
        const entropyBits = bits.slice(0, ENT);
        const checksumBits = bits.slice(ENT);

        const entropyBytesMatch = entropyBits.match(/(.{1,8})/g);
        if (!entropyBytesMatch) throw new InvalidMnemonicError('Invalid entropy bits');

        const entropyBuffer = Buffer.from(entropyBytesMatch.map(bin => parseInt(bin, 2)));

        const newChecksum = deriveChecksumBits(entropyBuffer);
        if (newChecksum !== checksumBits) {
            throw new InvalidChecksumError();
        }

        return true;

    } catch (e) {
        return false;
    }
}

