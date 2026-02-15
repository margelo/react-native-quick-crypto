import React from 'react';
import { DetailsScreen } from './DetailsScreen';

// @ts-expect-error - not dealing with navigation types rn
export const StressDetailsScreen = ({ route }) => (
  <DetailsScreen titlePrefix="Stress" route={route} />
);
