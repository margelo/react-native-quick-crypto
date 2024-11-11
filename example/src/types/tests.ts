import type { Suite } from "./suite";

export interface Tests {
  [key: string]: () => void;
}

export interface TestSuite extends Suite {
  tests: Tests;
}
