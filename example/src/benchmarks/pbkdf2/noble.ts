import { pbkdf2, pbkdf2Async } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha2';
import type { BenchmarkFn, ThemPbkdf2 } from '../../types/benchmarks';

const challenger = '@noble/hashes/pbkdf2';

const notes = ``;

const pbkdf2_256_32_32_async: BenchmarkFn = () => {
  pbkdf2Async(sha256, 'password', 'salt', { c: 32, dkLen: 32 });
};

const pbkdf2_256_32_32_sync: BenchmarkFn = () => {
  pbkdf2(sha256, 'password', 'salt', { c: 32, dkLen: 32 });
};

const benchmark: ThemPbkdf2 = {
  challenger,
  notes,
  pbkdf2_256_32_32_async,
  pbkdf2_256_32_32_sync,
};

export default benchmark;
