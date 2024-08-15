export type SuiteResults<T = TestResult | BenchmarkResult> = {
  [key: string]: SuiteResult<T>
}

export type SuiteResult<T> = {
  results: T[]
}

export type TestResult = {
  type: 'correct' | 'incorrect' | 'grouping'
  description: string
  errorMsg?: string
  indentation: number
  suiteName: string
}

export type BenchmarkResult = {
  type: 'faster' | 'slower' | 'grouping'
  description: string
  errorMsg?: string
  indentation: number
  us: number
  them: number
  suiteName: string
}

export type Stats = {
  start: Date
  end: Date
  duration: number
  suites: number
  tests: number
  passes: number
  pending: number
  failures: number
}
