export type MlKemVariant = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';

export const MLKEM_VARIANTS: MlKemVariant[] = [
  'ML-KEM-512',
  'ML-KEM-768',
  'ML-KEM-1024',
];

export const MLKEM_CIPHERTEXT_SIZES: Record<MlKemVariant, number> = {
  'ML-KEM-512': 768,
  'ML-KEM-768': 1088,
  'ML-KEM-1024': 1568,
};

export const SHARED_SECRET_SIZE = 32;
