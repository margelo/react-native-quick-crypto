import type { TestItemType } from '../navigators/children/Entry/TestItemType';
import { describe, it } from './MochaRNAdapter';
import { pbkdf2RegisterTests } from './Tests/pbkdf2Tests/pbkdf2Tests';
import { registerRandomTests } from './Tests/RandomTests/random';
import { registerHmacTests } from './Tests/HmacTests/HmacTests';
import { registerHashTests } from './Tests/HashTests/HashTests';
import { registerCipherTests1 } from './Tests/CipherTests/CipherTestFirst';
import { registerCipherTests2 } from './Tests/CipherTests/CipherTestSecond';
import chai from 'chai';

export const TEST_LIST: Array<TestItemType> = [
  {
    description: 'SimpleTests',
    value: false,
    registrator: () => {
      describe('basic tests', () => {
        it('basic 2 + 2 = 4', () => {
          chai.expect(2 + 2).to.be.eql(4);
        });

        it('2 + 2 = 3', () => {
          chai.expect(2 + 2).to.be.eql(3);
        });
      });
    },
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
];
