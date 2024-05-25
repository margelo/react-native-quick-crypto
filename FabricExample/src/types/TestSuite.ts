export type Suites = {
  [key: string]: Suite;
};

export type Suite = {
  value: boolean;
  count: number;
};
