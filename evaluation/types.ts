/**
 * HARIS (حارس) — Evaluation Dataset & Benchmark Types (v1.2.0)
 *
 * Defines strictly typed structures for evaluation test cases, ground truth labels,
 * Scam DNA expectations, adversarial taxonomy tags, and evaluation benchmark results.
 */

import { ScamType, FeatureKey } from '../lib/analysis/taxonomy';
import { RiskLevel } from '../lib/types/analysis';
import { ScreenshotInput } from '../lib/vision/schema';

export type EvaluationCategory = 'scam' | 'legitimate' | 'ambiguous';
export type Dialect = 'msa' | 'yemeni' | 'gulf' | 'egyptian' | 'mixed_en' | 'arabizi';

/**
 * Unified evaluation input contract matching production analyzeUnified
 */
export interface EvaluationInput {
  text?: string;
  url?: string;
  screenshot?: ScreenshotInput;
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
  isIndeterminate: boolean;
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

export interface ReproducibilityMetadata {
  datasetVersion: string;
  datasetSha256: string;
  runnerVersion: string;
  evaluationSourceCommit: string;
  artifactCommit: string;
  nodeVersion: string;
  geminiConfigured: boolean;
  geminiModel: string;
  pipelineMode: 'deterministic-baseline' | 'hybrid-gemini';
  evaluatedAt: string;
  configHash: string;
  evaluationConfig: {
    offlineMode: boolean;
    timeoutMs: number;
    maxAiScoreContribution: number;
    maxVisualScoreContribution: number;
  };
}

export interface DetailedConfusionMatrix {
  truePositives: number; // Scam correctly identified as high/suspicious (11)
  falsePositives: number; // Legitimate incorrectly identified as high/suspicious (2)
  falseNegatives: number; // Scam incorrectly identified as low (21)
  trueNegatives: number; // Legitimate correctly identified as low (18)
  scamIndeterminate: number; // Scam cases where visual extraction failed (2)
  legitimateIndeterminate: number; // Legitimate cases where visual extraction failed (2)
  ambiguousIndeterminate: number; // Ambiguous cases where visual extraction failed (1)
  totalIndeterminate: number; // Total extraction failures without text/URL fallback (5)
}

export interface RiskMetrics {
  coverageAdjustedAccuracy: number; // 30 / 70 (42.9%)
  determinateRiskAccuracy: number; // 30 / 65 (46.2%)
  totalCases: number; // 70
  determinateCasesCount: number; // 65
  indeterminateCasesCount: number; // 5
}

export interface LegitimateMetrics {
  legitimateAccuracy: number; // 18 / 22 (81.8%) — penalizing indeterminate
  legitimateDeterminateAccuracy: number; // 18 / 20 (90.0%) — TN / (TN + FP)
  legitimateIndeterminateCount: number; // 2
  legitimateIndeterminateRate: number; // 2 / 22 (9.1%)
  falsePositiveRate: number; // FP / (TN + FP) = 2 / 20 (10.0%)
  falsePositivesCount: number; // 2
  trueNegativesCount: number; // 18
  totalLegitimateCases: number; // 22
}

export interface ScamMetrics {
  truePositivesCount: number; // 11
  falseNegativesCount: number; // 21
  scamIndeterminateCount: number; // 2
  scamDeterminateDetectionRate: number; // TP / (TP + FN) = 11 / 32 (34.4%)
  scamDeterminateFNR: number; // FN / (TP + FN) = 21 / 32 (65.6%)
  scamMissRateIncludingIndeterminate: number; // (FN + Indet) / Total Scams = 23 / 34 (67.6%)
  totalScamCases: number; // 34
}

export interface ScamTypeMetrics {
  scamTypeScamOnlyDeterminateAccuracy: number; // 7 / 32 (21.9%)
  scamTypeScamOnlyCoverageAdjustedAccuracy: number; // 7 / 34 (20.6%)
  scamTypeScamOnlyIndeterminateRate: number; // 2 / 34 (5.9%)
  scamTypeAllCasesCoverageAdjusted: number; // 35 / 70 (50.0%)
}

export interface EvaluationSummary {
  version: string;
  evaluatedAt: string;
  metadata: ReproducibilityMetadata;
  totalCases: number;
  scamCases: number;
  legitimateCases: number;
  ambiguousCases: number;
  textUrlCases: number;
  screenshotCases: number;
  screenshotEvaluableCount: number;
  screenshotExtractionFailuresCount: number;

  riskMetrics: RiskMetrics;
  legitimateMetrics: LegitimateMetrics;
  scamMetrics: ScamMetrics;
  scamTypeMetrics: ScamTypeMetrics;

  confusionMatrix: DetailedConfusionMatrix;
  categoryBreakdown: Record<EvaluationCategory, CategoryMetric>;
  dialectBreakdown: Record<Dialect, DialectMetric>;
  featureMetrics: FeatureMetric[];
  caseResults: EvaluationCaseResult[];
}
