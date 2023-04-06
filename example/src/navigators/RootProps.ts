import type { BenchmarksProps } from './children/benchmarks/BenchmarksProps';
import type { EntryProps } from './children/Entry/EntryProps';
import type { TestingScreenProps } from './children/TestingScreen/TestingScreenProps';

export type RootStackParamList = {
  Entry: EntryProps;
  Benchmarks: BenchmarksProps;
  TestingScreen: TestingScreenProps;
};
