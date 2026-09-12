/**
 * HARIS (حارس) — Evaluation Dataset & Benchmark Types
 *
 * Defines strictly typed structures for evaluation test cases, ground truth labels,
 * Scam DNA expectations, adversarial taxonomy tags, and evaluation benchmark results.
 */

import { ScamType, FeatureKey } from '../lib/analysis/taxonomy';
import { RiskLevel } from '../lib/types/analysis';

export type EvaluationCategory = 'scam' | 'legitimate' | 'ambiguous';
export type Dialect = 'msa' | 'yemeni' | 'gulf' | 'egyptian' | 'mixed_en' | 'arabizi';

export interface EvaluationInput {
  text?: string;
  url?: string;
  screenshot?: {
    mimeType: string;
    data: string;
    description?: string;
  };
}

export interface EvaluationItem {
  id: string;
  title: string;
  description: string;
  category: EvaluationCategory;
  dialect: Dialect;
  input: EvaluationInput;
  expectedRiskCategory: RiskLevel; // 'low' | 'suspicious' | 'high'
  expectedScamType: ScamType;
  expectedDnaFeatures: FeatureKey[];
  adversarialSubtype?: string;
  rationale: string;
}

export interface EvaluationCaseResult {
  id: string;
  title: string;
  category: EvaluationCategory;
  dialect: Dialect;
  expectedRiskCategory: RiskLevel;
  actualRiskCategory: RiskLevel;
  riskScore: number;
  expectedScamType: ScamType;
  actualScamType: string;
  expectedDnaFeatures: FeatureKey[];
  actualDnaFeatures: FeatureKey[];
  isRiskCategoryCorrect: boolean;
  isScamTypeCorrect: boolean;
  isFalsePositive: boolean; // Legitimate classified as suspicious/high
  isFalseNegative: boolean; // Scam classified as low
  dnaTruePositives: number;
  dnaFalsePositives: number;
  dnaFalseNegatives: number;
  dnaPrecision: number;
  dnaRecall: number;
  dnaF1: number;
  aiConfidence: number | null;
  extractionConfidence: number | null;
  isExtractionFailure: boolean;
  notes?: string;
}

export interface FeatureMetric {
  featureId: FeatureKey;
  nameAr: string;
  nameEn: string;
  groundTruthCount: number;
  detectedCount: number;
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  precision: number;
  recall: number;
  f1: number;
}

export interface CategoryMetric {
  total: number;
  correctRisk: number;
  accuracy: number;
  averageScore: number;
}

export interface DialectMetric {
  total: number;
  correctRisk: number;
  accuracy: number;
}

export interface EvaluationSummary {
  version: string;
  evaluatedAt: string;
  environment: {
    geminiConfigured: boolean;
    nodeVersion: string;
  };
  totalCases: number;
  scamCases: number;
  legitimateCases: number;
  ambiguousCases: number;
  screenshotCases: number;
  overallAccuracy: number;
  scamTypeAccuracy: number;
  falsePositivesCount: number;
  falsePositiveRate: number;
  falseNegativesCount: number;
  falseNegativeRate: number;
  categoryBreakdown: Record<EvaluationCategory, CategoryMetric>;
  dialectBreakdown: Record<Dialect, DialectMetric>;
  featureMetrics: FeatureMetric[];
  caseResults: EvaluationCaseResult[];
}
