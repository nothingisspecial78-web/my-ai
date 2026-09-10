import { SafetyReport, SafetyInputType, RiskLevel, ConfidenceLevel } from '@/lib/safety/types';

export interface SafetyThemeContextFacts {
  inputType: SafetyInputType;
  riskLevel: RiskLevel;
  confidenceLevel: ConfidenceLevel;
  findingCount: number;
  report: SafetyReport;
}
