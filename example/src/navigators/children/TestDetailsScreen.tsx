import React from 'react';
import { DetailsScreen } from './DetailsScreen';

// @ts-expect-error - not dealing with navigation types rn
export const TestDetailsScreen = ({ route }) => (
  <DetailsScreen titlePrefix="Test" route={route} />
);
