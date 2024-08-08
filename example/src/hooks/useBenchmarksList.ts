import { useCallback, useState } from "react";
import { BenchmarkSuite, Suites } from "../types/Suite";

export const useBenchmarksList = (challenger: string): [
  Suites<BenchmarkSuite>,
  (description: string) => void,
  () => void,
  () => void,
] => {
  const [suites, setSuites] = useState<Suites<BenchmarkSuite>>(getInitialSuites(challenger));

  const toggle = useCallback(
    (description: string) => {
      setSuites((tests) => {
        tests[description]!.value = !tests[description]!.value;
        return tests;
      });
    },
    [setSuites]
  );

  const clearAll = useCallback(() => {
    setSuites((suites) => {
      Object.entries(suites).forEach(([_, suite]) => {
        suite.value = false;
      });
      return { ...suites };
    });
  }, [setSuites]);

  const checkAll = useCallback(() => {
    setSuites((suites) => {
      Object.entries(suites).forEach(([_, suite]) => {
        suite.value = true;
      });
      return { ...suites };
    });
  }, [setSuites]);
  return [suites, toggle, clearAll, checkAll];
};

const getInitialSuites = (challenger: string) => {
  const suiteNames = ['random', ];
  let suites: Suites<BenchmarkSuite> = {};
  suiteNames.forEach((suiteName) => {
    const {us, them} = loadBenchmarks(suiteName, challenger);
    suites[suiteName] = { value: false, count: 0, us, them };
  });

  // return count-enhanced list and totals
  return suites;
};

const loadBenchmarks = (suiteName: string, challenger: string) => {
  const us = allBenchmarks[`rnqc/${suiteName}`];
  const them = allBenchmarks[`${challenger}/${suiteName}`];
  return { us, them };
};

// can't use dynamic strings here, as require() is compile-time
const allBenchmarks: Record<string, Record<string, Function>> = {
  'rnqc/random': require('../benchmarks/rnqc/random').default,
  'crypto-browserify/random': require('../benchmarks/crypto-browserify/random').default,
}
