import type { TestItemType } from '../navigators/children/Entry/TestItemType';
import { pbkdf2RegisterTests } from './Tests/pbkdf2Tests/pbkdf2Tests';
import { registerRandomTests } from './Tests/RandomTests/random';
import { registerHmacTests } from './Tests/HmacTests/HmacTests';
import { registerHashTests } from './Tests/HashTests/HashTests';
import { registerCipherTests1 } from './Tests/CipherTests/CipherTestFirst';
import { registerCipherTests2 } from './Tests/CipherTests/CipherTestSecond';
import { registerConstantsTest } from './Tests/ConstantsTest/ConstantsTest';
import { registerPublicCipherTests } from './Tests/CipherTests/PublicCipherTests';
import { registerGenerateKeyPairTests } from './Tests/CipherTests/GenerateKeyPairTests';
import { registerSignTests } from './Tests/SignTests/SignTests';
import { webcryptoRegisterTests } from './Tests/webcryptoTests/webcryptoTests';

export const TEST_LIST: Array<TestItemType> = [
  {
    description: 'webcrypto',
    value: false,
    registrator: webcryptoRegisterTests,
  },
  {
    description: 'PBKDF2',
    value: false,
    registrator: pbkdf2RegisterTests,
  },
  {
    description: 'Random',
    value: false,
    registrator: registerRandomTests,
  },
  {
    description: 'Hmac',
    value: false,
    registrator: registerHmacTests,
  },
  {
    description: 'Hash',
    value: false,
    registrator: registerHashTests,
  },
  {
    description: 'createCipher/createDecipher',
    value: false,
    registrator: registerCipherTests1,
  },
  {
    description: 'createCipheriv/createDecipheriv',
    value: false,
    registrator: registerCipherTests2,
  },
  {
    description: 'constants',
    value: false,
    registrator: registerConstantsTest,
  },
  {
    description: 'public cipher',
    value: false,
    registrator: registerPublicCipherTests,
  },
  {
    description: 'generateKeyPair',
    value: false,
    registrator: registerGenerateKeyPairTests,
  },
  {
    description: 'sign/verify',
    value: false,
    registrator: registerSignTests,
  },
];
