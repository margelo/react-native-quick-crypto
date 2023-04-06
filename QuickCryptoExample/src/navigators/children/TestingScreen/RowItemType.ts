export type RowItemType = {
  type: 'correct' | 'incorrect' | 'grouping';
  description: string;
  errorMsg?: string;
  indentation: number;
  key: string;
};
