/* eslint-disable @typescript-eslint/no-require-imports */
import React, { createContext, useCallback, useState } from 'react';
import type { Suites } from '../types/suite';
import type { BenchmarkImports, BenchmarkSuite } from '../types/benchmarks';
import type { BenchmarkResult, SuiteResults } from '../types/results';

export const BenchmarkContext = createContext<{
  suites: Suites<BenchmarkSuite>;
  setRunning: (suiteName: string, running: boolean) => void;
  toggle: (description: string) => void;
  clearAll: () => void;
  checkAll: () => void;
  runCount: number;
  setRunCount: (runCount: number) => void;
  results: SuiteResults<BenchmarkResult>;
  setResults: (results: SuiteResults<BenchmarkResult>) => void;
  addResult: (newResult: BenchmarkResult) => void;
}>(
  {
    suites: {},
    setRunning: () => {},
    toggle: () => {},
    clearAll: () => {},
    checkAll: () => {},
    runCount: 0,
    setRunCount: () => {},
    results: {},
    setResults: () => {},
    addResult: () => {},
  }
);

export const BenchmarkContextProvider = ({ children }: { children: React.ReactNode }) => {
  const [suites, setSuites] = useState<Suites<BenchmarkSuite>>(loadBenchmarks());
  const [runCount, setRunCount] = useState<number>(100);
  const [results, setResults] = useState<SuiteResults<BenchmarkResult>>({});

  const setRunning = (suiteName: string, running: boolean) => {
    setSuites(prev => {
      prev[suiteName]!.running = running;
      console.log('prev', prev[suiteName]!.running);
      return { ...prev };
    });
  };

  const toggle = useCallback(
    (description: string) => {
      setSuites(prev => {
        prev[description]!.value = !prev[description]!.value;
        return prev;
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

  const addResult = useCallback(
    (newResult: BenchmarkResult) => {
      setResults(prev => {
        if (!prev[newResult.suiteName]) {
          prev[newResult.suiteName] = { results: [] };
        }
        prev[newResult.suiteName]?.results.push(newResult);
        return { ...prev };
      });
    },
    [setResults],
  );


  // const runBenchmarks = () => {
  //   setResults({});
  //   Object.entries(suites).forEach(([suiteName, suite]) => {
  //     if (suite.value) {
  //       setRunning(suiteName, true);
  //       const results: FnResult[] = [];
  //       suite.benchmarks.forEach((library) => {
  //         Object.entries(library).forEach(([libName, bench]) => {
  //           let challenger = '';
  //           let notes = '';
  //           Object.entries(bench).forEach(([fnName, fn]) => {
  //             if (typeof fn !== 'function') {
  //               if (fn === 'challenger') {
  //                 challenger = fn;
  //               }
  //               if (fn === 'notes') {
  //                 notes = fn;
  //               }
  //               return;
  //             }
  //             // TODO: const [time, error] & put error.msg in result
  //             const time = runBenchmark(fn, runCount);
  //             results.push({
  //               libName,
  //               challenger,
  //               notes,
  //               fnName,
  //               time,
  //             });
  //           })
  //         });
  //         addResult({
  //           suiteName,
  //           results,
  //         });
  //       });
  //       setRunning(suiteName, false);
  //     }
  //   });
  // };

  // /**
  //  *
  //  * @param fn benchmark function
  //  * @param runCount how many times to run the function
  //  * @returns time in ms
  //  */
  // // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
  // const runBenchmark = (fn: Function, runCount: number): number => {
  //   // warm up imports, etc.
  //   fn();

  //   // do the actual benchmark
  //   const start = performance.now();
  //   for (let i = 0; i < runCount; i++) {
  //     fn();
  //   }
  //   const end = performance.now();
  //   return end - start;
  // };

  return (
    <BenchmarkContext.Provider value={{
      suites, setRunning, toggle, clearAll, checkAll,
      runCount, setRunCount, results, setResults, addResult,
    }}>
      {children}
    </BenchmarkContext.Provider>
  );
};


const loadBenchmarks = () => {
  const imports: BenchmarkImports = {
    random: [
      { rnqc: require('../benchmarks/random/rnqc').default },
      { browserify: require('../benchmarks/random/browserify').default },
    ],
    pbkdf2: [
      { rnqc: require('../benchmarks/pbkdf2/rnqc').default },
      { noble: require('../benchmarks/pbkdf2/noble').default },
      { browserify: require('../benchmarks/pbkdf2/browserify').default },
    ],
  };

  const suites: Suites<BenchmarkSuite> = {};
  Object.entries(imports).forEach(([suiteName, benchmarks]) => {
    suites[suiteName] = { name: suiteName, value: false, benchmarks };
  });

  // return count-enhanced list and totals
  return suites;
};
