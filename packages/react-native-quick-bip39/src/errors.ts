export class BIP39Error extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'BIP39Error';
    }
}

export class InvalidMnemonicError extends BIP39Error {
    constructor(message: string = 'Invalid mnemonic') {
        super(message);
        this.name = 'InvalidMnemonicError';
    }
}

export class InvalidEntropyError extends BIP39Error {
    constructor(message: string = 'Invalid entropy') {
        super(message);
        this.name = 'InvalidEntropyError';
    }
}

export class InvalidChecksumError extends BIP39Error {
    constructor(message: string = 'Invalid mnemonic checksum') {
        super(message);
        this.name = 'InvalidChecksumError';
    }
}
