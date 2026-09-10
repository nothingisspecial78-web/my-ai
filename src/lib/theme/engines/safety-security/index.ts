import { ThemeImplementation } from '../../engine';
import { SafetySecurityAnalyzer } from './analyzer';
import { SafetySecurityEngine } from './engine';

export const safetySecurityImpl: ThemeImplementation = {
  analyzer: new SafetySecurityAnalyzer(),
  engine: new SafetySecurityEngine(),
};

export * from './types';
