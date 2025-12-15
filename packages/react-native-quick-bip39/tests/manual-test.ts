import { generateMnemonic, mnemonicToSeed, validateMnemonic } from './src/index';

async function test() {
    console.log('--- BIP39 Test ---');

    try {
        const mnemonic = generateMnemonic(128);
        console.log('Generated Mnemonic:', mnemonic);

        const isValid = validateMnemonic(mnemonic);
        console.log('Is Valid:', isValid);

        console.time('mnemonicToSeed');
        // Random Key derivation verification
        const seed = await mnemonicToSeed(mnemonic);
        console.timeEnd('mnemonicToSeed');

        console.log('Seed (Hex):', seed.toString('hex').slice(0, 32) + '...');
    } catch (e) {
        console.error('Test failed:', e);
    }
}

test();
