import { useCallback, useState } from 'react';
import type { Benchmark, BenchmarkSuite, Suites } from '../types/Suite';
import type { BenchmarkFn } from '../benchmarks/types';

export const useBenchmarksList = (
  challenger: string,
): [
  Suites<BenchmarkSuite>,
  (description: string) => void,
  () => void,
  () => void,
] => {
  const [suites, setSuites] = useState<Suites<BenchmarkSuite>>(
    getInitialSuites(challenger),
  );

  const toggle = useCallback(
    (description: string) => {
      setSuites(tests => {
        tests[description]!.value = !tests[description]!.value;
        return tests;
      });
    },
    [setSuites],
  );

  const clearAll = useCallback(() => {
    setSuites(prev => {
      Object.values(prev).forEach(suite => {
        suite.value = false;
      });
      return { ...prev };
    });
  }, [setSuites]);

  const checkAll = useCallback(() => {
    setSuites(prev => {
      Object.values(prev).forEach(suite => {
        suite.value = true;
      });
      return { ...prev };
    });
  }, [setSuites]);

  return [suites, toggle, clearAll, checkAll];
};

const getInitialSuites = (challenger: string) => {
  const suiteNames: string[] = [
    // random - all challengers use `crypto` too,so the comparison is to 'us' - maybe skip in future
    'random',
  ];
  const suites: Suites<BenchmarkSuite> = {};
  suiteNames.forEach(suiteName => {
    const benchmarks = loadBenchmarks(suiteName, challenger);
    suites[suiteName] = { value: false, count: benchmarks.length, benchmarks };
  });

  // return count-enhanced list and totals
  return suites;
};

const loadBenchmarks = (suiteName: string, challenger: string): Benchmark[] => {
  const us = allBenchmarks[`rnqc/${suiteName}`];
  const them = allBenchmarks[`${challenger}/${suiteName}`];
  if (!us || !them) {
    throw new Error(`Could not load benchmarks for ${suiteName}`);
  }
  const ret: Benchmark[] = [];
  const themKeys = Object.keys(them);
  // add all 'us' benchmarks
  Object.entries(us).forEach(([name, fn]) => {
    ret.push({ name, us: fn, them: them[name] });
    // remove from themKeys
    themKeys.splice(themKeys.indexOf(name), 1);
  });
  // add all 'them' benchmarks that are not in 'us'
  themKeys.forEach(name => {
    ret.push({ name, us: us[name], them: them[name] });
  });
  return ret;
};

// can't use dynamic strings here, as require() is compile-time
/* eslint-disable @typescript-eslint/no-require-imports */
const allBenchmarks: Record<string, Record<string, BenchmarkFn>> = {
  'rnqc/random': require('../benchmarks/rnqc/random').default,
  'crypto-browserify/random': require('../benchmarks/crypto-browserify/random')
    .default,
};
