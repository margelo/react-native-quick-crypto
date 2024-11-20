/* eslint-disable @typescript-eslint/no-require-imports */
import { useEffect, useState } from "react";
import { BenchmarkSuite } from "../benchmarks/benchmarks";

export const useBenchmarks = (): [
  BenchmarkSuite[],
  (name: string) => void,
  () => void,
  () => void,
  () => void,
] => {
  const [suites, setSuites] = useState<BenchmarkSuite[]>([]);

  // initial load of benchmark suites
  useEffect(() => {
    const newSuites: BenchmarkSuite[] = [];
    newSuites.push(random());
    setSuites(newSuites);
  }, []);

  const updateSuites = (fn: (suite: BenchmarkSuite) => void) => {
    if (!suites.length) return;
    const copy = [ ...suites ];
    copy.forEach(fn);
    setSuites(copy);
  };

  const toggle = (name: string) => updateSuites(suite => {
    if (suite.name === name) {
      suite.enabled = !suite.enabled;
    }
  });

  const checkAll = () => updateSuites(suite => {
    suite.enabled = true;
  });

  const clearAll = () => updateSuites(suite => {
    suite.enabled = false;
  });

  const runBenchmarks = () => updateSuites(suite => {
    if (suite.enabled && suite.state !== 'running') {
      suite.state = 'running';
    }
  });

  return [suites, toggle, checkAll, clearAll, runBenchmarks];
};

const random = () => {
  const suite = new BenchmarkSuite('random');
  suite.addBenchmark(require('../benchmarks/random/randomBytes').randomBytes10);
  suite.addBenchmark(require('../benchmarks/random/randomBytes').randomBytes1024);
  return suite;
};
