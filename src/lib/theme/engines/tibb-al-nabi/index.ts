import { ThemeImplementation } from '../../engine';
import { TibbAlNabiAnalyzer } from './analyzer';
import { TibbAlNabiEngine } from './engine';

export const tibbAlNabiImpl: ThemeImplementation = {
  analyzer: new TibbAlNabiAnalyzer(),
  engine: new TibbAlNabiEngine(),
};

export * from './types';
export * from './constants';
