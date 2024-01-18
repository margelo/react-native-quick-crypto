import type { TestItemType } from '../navigators/children/Entry/TestItemType';
import { pbkdf2RegisterTests } from './Tests/pbkdf2Tests/pbkdf2Tests';
import { registerRandomTests } from './Tests/RandomTests/randomTests';
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
    count: 0,
  },
  {
    description: 'pbkdf2',
    value: false,
    registrator: pbkdf2RegisterTests,
    count: 0,
  },
  {
    description: 'random',
    value: false,
    registrator: registerRandomTests,
    count: 0,
  },
  {
    description: 'hmac',
    value: false,
    registrator: registerHmacTests,
    count: 0,
  },
  {
    description: 'hash',
    value: false,
    registrator: registerHashTests,
    count: 0,
  },
  {
    description: 'createCipher/createDecipher',
    value: false,
    registrator: registerCipherTests1,
    count: 0,
  },
  {
    description: 'createCipheriv/createDecipheriv',
    value: false,
    registrator: registerCipherTests2,
    count: 0,
  },
  {
    description: 'constants',
    value: false,
    registrator: registerConstantsTest,
    count: 0,
  },
  {
    description: 'public cipher',
    value: false,
    registrator: registerPublicCipherTests,
    count: 0,
  },
  {
    description: 'generateKeyPair',
    value: false,
    registrator: registerGenerateKeyPairTests,
    count: 0,
  },
  {
    description: 'sign/verify',
    value: false,
    registrator: registerSignTests,
    count: 0,
  },
];
