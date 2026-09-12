/**
 * HARIS (حارس) — Pure Evaluation Metric Functions (v1.2.0)
 *
 * Standalone, strictly tested pure functions for calculating confusion matrix,
 * coverage-adjusted vs. determinate accuracy, false positive / negative rates,
 * Scam DNA precision/recall/F1, and scam-type attribution.
 */

import {
  EvaluationCaseResult,
  DetailedConfusionMatrix,
  RiskMetrics,
  LegitimateMetrics,
  ScamMetrics,
  ScamTypeMetrics,
  FeatureMetric,
  CategoryMetric,
  DialectMetric,
  EvaluationCategory,
  Dialect,
} from './types';
import { SCAM_DNA_FEATURES, FeatureKey } from '../lib/analysis/taxonomy';

/**
 * Calculate binary confusion matrix including granular indeterminate breakdowns
 */
export function calculateConfusionMatrix(caseResults: EvaluationCaseResult[]): DetailedConfusionMatrix {
  let tp = 0;
  let fp = 0;
  let fn = 0;
  let tn = 0;
  let scamIndet = 0;
  let legitIndet = 0;
  let ambigIndet = 0;

  for (const c of caseResults) {
    if (c.isIndeterminate) {
      if (c.category === 'scam') scamIndet++;
      else if (c.category === 'legitimate') legitIndet++;
      else ambigIndet++;
    } else if (c.category === 'scam') {
      if (c.actualRiskCategory === 'high' || c.actualRiskCategory === 'suspicious') {
        tp++;
      } else if (c.actualRiskCategory === 'low') {
        fn++;
      }
    } else if (c.category === 'legitimate') {
      if (c.actualRiskCategory === 'low') {
        tn++;
      } else if (c.actualRiskCategory === 'suspicious' || c.actualRiskCategory === 'high') {
        fp++;
      }
    }
  }

  return {
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    trueNegatives: tn,
    scamIndeterminate: scamIndet,
    legitimateIndeterminate: legitIndet,
    ambiguousIndeterminate: ambigIndet,
    totalIndeterminate: scamIndet + legitIndet + ambigIndet,
  };
}

/**
 * Calculate overall risk classification metrics: coverage-adjusted vs. determinate
 */
export function calculateRiskMetrics(
  caseResults: EvaluationCaseResult[],
  matrix: DetailedConfusionMatrix
): RiskMetrics {
  const totalCases = caseResults.length;
  const indeterminateCasesCount = matrix.totalIndeterminate;
  const determinateCasesCount = totalCases - indeterminateCasesCount;

  const totalCorrect = caseResults.filter((c) => c.isRiskCategoryCorrect).length;
  const determinateCorrect = caseResults.filter((c) => c.isRiskCategoryCorrect && !c.isIndeterminate).length;

  const coverageAdjustedAccuracy = totalCases > 0 ? Number((totalCorrect / totalCases).toFixed(3)) : 0;
  const determinateRiskAccuracy = determinateCasesCount > 0 ? Number((determinateCorrect / determinateCasesCount).toFixed(3)) : 0;

  return {
    coverageAdjustedAccuracy,
    determinateRiskAccuracy,
    totalCases,
    determinateCasesCount,
    indeterminateCasesCount,
  };
}

/**
 * Calculate legitimate message evaluation metrics: specificity, FPR, and indeterminate rates
 */
export function calculateLegitimateMetrics(
  caseResults: EvaluationCaseResult[],
  matrix: DetailedConfusionMatrix
): LegitimateMetrics {
  const legitimateCases = caseResults.filter((c) => c.category === 'legitimate');
  const totalLegitimateCases = legitimateCases.length;
  const tn = matrix.trueNegatives;
  const fp = matrix.falsePositives;
  const determinateLegitCount = tn + fp; // Denominator for true FPR

  const falsePositiveRate = determinateLegitCount > 0 ? Number((fp / determinateLegitCount).toFixed(3)) : 0;
  const legitimateDeterminateAccuracy = determinateLegitCount > 0 ? Number((tn / determinateLegitCount).toFixed(3)) : 0;
  const legitimateAccuracy = totalLegitimateCases > 0 ? Number((tn / totalLegitimateCases).toFixed(3)) : 0;
  const legitimateIndeterminateRate = totalLegitimateCases > 0 ? Number((matrix.legitimateIndeterminate / totalLegitimateCases).toFixed(3)) : 0;

  return {
    legitimateAccuracy,
    legitimateDeterminateAccuracy,
    legitimateIndeterminateCount: matrix.legitimateIndeterminate,
    legitimateIndeterminateRate,
    falsePositiveRate,
    falsePositivesCount: fp,
    trueNegativesCount: tn,
    totalLegitimateCases,
  };
}

/**
 * Calculate scam detection metrics: recall, determinate FNR, and miss rate including indeterminate
 */
export function calculateScamMetrics(
  caseResults: EvaluationCaseResult[],
  matrix: DetailedConfusionMatrix
): ScamMetrics {
  const scamCases = caseResults.filter((c) => c.category === 'scam');
  const totalScamCases = scamCases.length;
  const tp = matrix.truePositives;
  const fn = matrix.falseNegatives;
  const determinateScamCount = tp + fn; // Denominator for determinate FNR

  const scamDeterminateDetectionRate = determinateScamCount > 0 ? Number((tp / determinateScamCount).toFixed(3)) : 0;
  const scamDeterminateFNR = determinateScamCount > 0 ? Number((fn / determinateScamCount).toFixed(3)) : 0;
  const scamMissRateIncludingIndeterminate = totalScamCases > 0 ? Number(((fn + matrix.scamIndeterminate) / totalScamCases).toFixed(3)) : 0;

  return {
    truePositivesCount: tp,
    falseNegativesCount: fn,
    scamIndeterminateCount: matrix.scamIndeterminate,
    scamDeterminateDetectionRate,
    scamDeterminateFNR,
    scamMissRateIncludingIndeterminate,
    totalScamCases,
  };
}

/**
 * Calculate scam-type attribution metrics with strict isolation of UNKNOWN matches
 */
export function calculateScamTypeMetrics(caseResults: EvaluationCaseResult[]): ScamTypeMetrics {
  const totalCases = caseResults.length;
  const scamCases = caseResults.filter((c) => c.category === 'scam');
  const totalScamCases = scamCases.length;

  const determinateScams = scamCases.filter((c) => !c.isIndeterminate);
  const correctNonUnknownInDeterminateScams = determinateScams.filter(
    (c) => c.isScamTypeCorrect && c.actualScamType !== 'UNKNOWN'
  ).length;

  const correctScamTypeAllCases = caseResults.filter((c) => c.isScamTypeCorrect).length;

  const scamTypeScamOnlyDeterminateAccuracy =
    determinateScams.length > 0 ? Number((correctNonUnknownInDeterminateScams / determinateScams.length).toFixed(3)) : 0;

  const scamTypeScamOnlyCoverageAdjustedAccuracy =
    totalScamCases > 0 ? Number((correctNonUnknownInDeterminateScams / totalScamCases).toFixed(3)) : 0;

  const scamTypeScamOnlyIndeterminateRate =
    totalScamCases > 0 ? Number((scamCases.filter((c) => c.isIndeterminate).length / totalScamCases).toFixed(3)) : 0;

  const scamTypeAllCasesCoverageAdjusted =
    totalCases > 0 ? Number((correctScamTypeAllCases / totalCases).toFixed(3)) : 0;

  return {
    scamTypeScamOnlyDeterminateAccuracy,
    scamTypeScamOnlyCoverageAdjustedAccuracy,
    scamTypeScamOnlyIndeterminateRate,
    scamTypeAllCasesCoverageAdjusted,
  };
}

/**
 * Calculate precision with safe divide-by-zero handling
 */
export function calculatePrecision(tp: number, fp: number): number {
  if (tp + fp === 0) return 0;
  return Number((tp / (tp + fp)).toFixed(3));
}

/**
 * Calculate recall with safe divide-by-zero handling
 */
export function calculateRecall(tp: number, fn: number): number {
  if (tp + fn === 0) return 0;
  return Number((tp / (tp + fn)).toFixed(3));
}

/**
 * Calculate F1 score with safe divide-by-zero handling
 */
export function calculateF1(precision: number, recall: number): number {
  if (precision + recall === 0) return 0;
  return Number(((2 * precision * recall) / (precision + recall)).toFixed(3));
}

/**
 * Aggregate Scam DNA feature metrics across all test cases
 */
export function calculateFeatureMetrics(
  caseResults: EvaluationCaseResult[]
): FeatureMetric[] {
  const stats = {} as Record<FeatureKey, { groundTruth: number; detected: number; tp: number; fp: number; fn: number }>;

  for (const feat of SCAM_DNA_FEATURES) {
    stats[feat] = { groundTruth: 0, detected: 0, tp: 0, fp: 0, fn: 0 };
  }

  for (const c of caseResults) {
    const expSet = new Set(c.expectedDnaFeatures);
    const actSet = new Set(c.actualDnaFeatures);

    for (const feat of SCAM_DNA_FEATURES) {
      const exp = expSet.has(feat);
      const act = actSet.has(feat);
      if (exp) stats[feat].groundTruth++;
      if (act) stats[feat].detected++;
      if (exp && act) stats[feat].tp++;
      if (!exp && act) stats[feat].fp++;
      if (exp && !act) stats[feat].fn++;
    }
  }

  return SCAM_DNA_FEATURES.map((feat) => {
    const s = stats[feat];
    const precision = calculatePrecision(s.tp, s.fp);
    const recall = calculateRecall(s.tp, s.fn);
    const f1 = calculateF1(precision, recall);

    return {
      featureId: feat,
      nameAr: feat,
      nameEn: feat,
      groundTruthCount: s.groundTruth,
      detectedCount: s.detected,
      truePositives: s.tp,
      falsePositives: s.fp,
      falseNegatives: s.fn,
      precision,
      recall,
      f1,
    };
  });
}

/**
 * Aggregate category-level breakdown metrics
 */
export function calculateCategoryMetrics(
  caseResults: EvaluationCaseResult[]
): Record<EvaluationCategory, CategoryMetric> {
  const categories: EvaluationCategory[] = ['scam', 'legitimate', 'ambiguous'];
  const out = {} as Record<EvaluationCategory, CategoryMetric>;

  for (const cat of categories) {
    const subset = caseResults.filter((c) => c.category === cat);
    const total = subset.length;
    const correctRisk = subset.filter((c) => c.isRiskCategoryCorrect).length;
    const accuracy = total > 0 ? Number((correctRisk / total).toFixed(3)) : 0;
    const totalScore = subset.reduce((acc, c) => acc + c.riskScore, 0);
    const averageScore = total > 0 ? Number((totalScore / total).toFixed(1)) : 0;

    out[cat] = {
      total,
      correctRisk,
      accuracy,
      averageScore,
    };
  }

  return out;
}

/**
 * Aggregate dialect/regional breakdown metrics
 */
export function calculateDialectMetrics(
  caseResults: EvaluationCaseResult[]
): Record<Dialect, DialectMetric> {
  const dialects: Dialect[] = ['msa', 'yemeni', 'gulf', 'egyptian', 'mixed_en', 'arabizi'];
  const out = {} as Record<Dialect, DialectMetric>;

  for (const d of dialects) {
    const subset = caseResults.filter((c) => c.dialect === d);
    const total = subset.length;
    const correctRisk = subset.filter((c) => c.isRiskCategoryCorrect).length;
    const accuracy = total > 0 ? Number((correctRisk / total).toFixed(3)) : 0;

    out[d] = {
      total,
      correctRisk,
      accuracy,
    };
  }

  return out;
}
