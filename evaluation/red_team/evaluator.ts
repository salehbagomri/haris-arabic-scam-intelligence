/**
 * HARIS (حارس) — Adversarial Red-Team Evaluator (v1.0.0 — Phase 6B)
 *
 * Standalone, strictly tested evaluation runner for assessing adversarial resilience,
 * classifying failure modes, detecting evidence integrity violations, and computing
 * granular red-team metrics.
 */

import { analyzeUnified } from '../../lib/vision/pipeline';
import { SCAM_DNA_FEATURES, FeatureKey } from '../../lib/analysis/taxonomy';
import {
  RedTeamItem,
  RedTeamCaseResult,
  RedTeamCaseFailure,
  EvidenceIntegrityViolation,
  RedTeamBenchmarkSummary,
  RedTeamTaxonomyCategory,
  RED_TEAM_CATEGORIES,
  RED_TEAM_CATEGORY_NAMES,
  CategoryMetricSummary,
  DialectMetricSummary,
  ModalityMetricSummary,
  DnaFeatureRecallSummary,
  AdversarialFailureCategory,
  FailureSeverity,
  AttackModality,
} from './types';

/**
 * Normalizes Arabic text for substring containment checks
 */
export function normalizeForContainment(str: string): string {
  return str
    .toLowerCase()
    .replace(/[\u200B-\u200D\uFEFF\u00A0]/g, ' ') // Replace zero-width & invisible format characters with space
    .replace(/[\u064B-\u065F\u0670]/g, '') // Remove Arabic diacritics
    .replace(/\u0640/g, '') // Remove tatweel
    .replace(/[أإآ]/g, 'ا') // Normalize alif
    .replace(/ة/g, 'ه') // Normalize ta marbuta
    .replace(/ى/g, 'ي') // Normalize alif maqsura
    .replace(/\s+/g, ' ') // Collapse whitespace
    .trim();
}

/**
 * Evaluates a single Red-Team adversarial item against production analyzeUnified
 */
export async function evaluateRedTeamItem(item: RedTeamItem): Promise<RedTeamCaseResult> {
  const result = await analyzeUnified(item.input);

  const actualRiskCategory = result.riskLevel;
  const isIndeterminate = Boolean(result.isExtractionFailure);
  const actualScamType = result.scamType;
  const actualDnaFeatures = (result.detectedFeatures || []) as FeatureKey[];

  const isRiskCategoryCorrect = isIndeterminate ? false : actualRiskCategory === item.expectedRiskCategory;

  const isFalsePositive =
    item.expectedRiskCategory === 'low' &&
    (actualRiskCategory === 'suspicious' || actualRiskCategory === 'high');

  const isFalseNegative =
    (item.expectedRiskCategory === 'high' || item.expectedRiskCategory === 'suspicious') &&
    actualRiskCategory === 'low' &&
    !isIndeterminate;

  let isScamTypeCorrect = false;
  if (item.expectedScamType === 'UNKNOWN') {
    isScamTypeCorrect = actualScamType === 'UNKNOWN';
  } else {
    isScamTypeCorrect = actualScamType === item.expectedScamType;
  }

  const failures: RedTeamCaseFailure[] = [];
  const evidenceIntegrityViolations: EvidenceIntegrityViolation[] = [];

  // 1. False Negative Failure
  if (isFalseNegative) {
    const severity: FailureSeverity = item.expectedRiskCategory === 'high' ? 'Critical' : 'High';
    failures.push({
      category: 'FALSE_NEGATIVE',
      severity,
      description: `Scam evasion successful: expected ${item.expectedRiskCategory.toUpperCase()} risk, but engine classified as LOW (Score: ${result.riskScore}).`,
    });
  }

  // 2. False Positive Failure
  if (isFalsePositive) {
    const severity: FailureSeverity = actualRiskCategory === 'high' ? 'Critical' : 'High';
    failures.push({
      category: 'FALSE_POSITIVE',
      severity,
      description: `False alarm on benign stress input: expected LOW risk, but engine classified as ${actualRiskCategory.toUpperCase()} (Score: ${result.riskScore}).`,
    });
  }

  // 3. Extraction / Indeterminate Failure
  if (isIndeterminate) {
    failures.push({
      category: 'EXTRACTION_FAILURE',
      severity: 'Medium',
      description: `Unextracted screenshot or degraded input resulted in indeterminate analysis state.`,
    });
  }

  // 4. Contradictory Fusion / Decoy URL Failure
  if (
    (item.taxonomyCategory === 'multiple_contradictory_urls' ||
      item.taxonomyCategory === 'contradictory_evidence_fusion') &&
    item.expectedRiskCategory === 'high' &&
    actualRiskCategory !== 'high'
  ) {
    failures.push({
      category: 'CONTRADICTORY_FUSION_FAILURE',
      severity: 'Critical',
      description: `Signal dilution or decoy URL bypassed threat detection (actual risk: ${actualRiskCategory}).`,
    });
  }

  // 5. Wrong Scam Type Failure (if risk was correctly or partially detected)
  if (
    item.expectedScamType !== 'UNKNOWN' &&
    (actualRiskCategory === 'high' || actualRiskCategory === 'suspicious') &&
    !isScamTypeCorrect
  ) {
    failures.push({
      category: 'WRONG_SCAM_TYPE',
      severity: 'Medium',
      description: `Misattribution of threat category: expected ${item.expectedScamType}, but attributed to ${actualScamType}.`,
    });
  }

  // 6. Missed Scam DNA Features
  const missedDna = item.expectedDnaFeatures.filter((feat) => !actualDnaFeatures.includes(feat));
  if (missedDna.length > 0 && (actualRiskCategory === 'high' || actualRiskCategory === 'suspicious')) {
    failures.push({
      category: 'MISSED_DNA',
      severity: missedDna.length === item.expectedDnaFeatures.length ? 'High' : 'Low',
      description: `Missed expected Scam DNA feature(s): [${missedDna.join(', ')}].`,
    });
  }

  // =========================================================================
  // Evidence Integrity Verification
  // =========================================================================

  // A. Check for evidence quote hallucination / ungrounded quotes
  const sourceText = item.input.text || '';
  const sourceUrl = item.input.url || '';
  const combinedSource = `${sourceText} ${sourceUrl}`;
  const normalizedSource = normalizeForContainment(combinedSource);

  for (const indicator of result.scamDna || []) {
    for (const quote of indicator.evidence || []) {
      if (quote && quote.trim().length > 3 && item.modality !== 'screenshot') {
        const normalizedQuote = normalizeForContainment(quote);
        if (!normalizedSource.includes(normalizedQuote)) {
          evidenceIntegrityViolations.push({
            rule: 'ungrounded_evidence_quote',
            description: `Evidence quote "${quote}" is not grounded in source input text.`,
            severity: 'High',
          });
          failures.push({
            category: 'UNSUPPORTED_EVIDENCE',
            severity: 'High',
            description: `Evidence quote "${quote}" was fabricated or not present in input.`,
          });
        }
      }
    }
  }

  // B. Forbidden DNA Features Violation (e.g. brand mention turned to impersonation)
  if (item.forbiddenDnaFeatures && item.forbiddenDnaFeatures.length > 0) {
    for (const forbidden of item.forbiddenDnaFeatures) {
      if (actualDnaFeatures.includes(forbidden)) {
        let rule = `forbidden_feature_${forbidden}`;
        let description = `Forbidden feature '${forbidden}' was triggered on a non-scam input.`;

        if (forbidden === 'impersonation') {
          rule = 'mere_brand_mention_as_impersonation';
          description = 'Mere brand mention in inquiry/news was falsely promoted to impersonation.';
        } else if (forbidden === 'otp_request') {
          rule = 'negative_otp_warning_as_scam';
          description = 'Negative security advisory mentioning OTP was falsely treated as OTP harvesting request.';
        } else if (forbidden === 'threat_language') {
          rule = 'operational_urgency_as_threat';
          description = 'Legitimate operational deadline was falsely treated as threat language.';
        }

        evidenceIntegrityViolations.push({
          rule,
          description,
          severity: 'High',
        });

        failures.push({
          category: 'UNSUPPORTED_EVIDENCE',
          severity: 'High',
          description,
        });
      }
    }
  }

  // C. Benign institutional domain treated as high risk
  if (item.taxonomyCategory === 'benign_suspicious_domains' && actualRiskCategory === 'high') {
    evidenceIntegrityViolations.push({
      rule: 'benign_domain_treated_as_high_risk',
      description: `Authorized institutional/educational domain flagged as high-risk scam without malicious evidence.`,
      severity: 'Critical',
    });
  }

  // D. High risk declared without any evidence items
  if (actualRiskCategory === 'high' && (result.evidence || []).length === 0) {
    evidenceIntegrityViolations.push({
      rule: 'unsubstantiated_high_risk_verdict',
      description: `High risk level assigned with zero supporting evidence items.`,
      severity: 'Critical',
    });
  }

  const evidenceItems = (result.evidence || []).map((e) => ({
    type: e.source,
    description: e.description,
    quote: e.title,
    severity: e.severity,
    source: e.provenance,
  }));

  return {
    id: item.id,
    title: item.title,
    taxonomyCategory: item.taxonomyCategory,
    taxonomyCategoryName: RED_TEAM_CATEGORY_NAMES[item.taxonomyCategory],
    dialect: item.dialect,
    modality: item.modality,
    expectedRiskCategory: item.expectedRiskCategory,
    actualRiskCategory,
    riskScore: result.riskScore,
    expectedScamType: item.expectedScamType,
    actualScamType,
    expectedDnaFeatures: item.expectedDnaFeatures,
    actualDnaFeatures,
    isRiskCategoryCorrect,
    isScamTypeCorrect,
    isFalsePositive,
    isFalseNegative,
    isIndeterminate,
    evidenceItemsCount: evidenceItems.length,
    evidenceItems,
    uncertainties: result.uncertainties || [],
    actionableAdvice: result.actionableAdvice || [],
    aiConfidence: result.aiConfidence ?? null,
    extractionConfidence: result.visualExtraction?.extractionConfidence ?? null,
    failures,
    evidenceIntegrityViolations,
    hasFailure: failures.length > 0 || evidenceIntegrityViolations.length > 0,
  };
}

/**
 * Calculate aggregate Red-Team benchmark summary metrics
 */
export function calculateRedTeamSummary(
  caseResults: RedTeamCaseResult[],
  metadata: RedTeamBenchmarkSummary['metadata']
): RedTeamBenchmarkSummary {
  const totalCases = caseResults.length;
  const failedCasesCount = caseResults.filter((c) => c.hasFailure).length;
  const overallFailureRate = totalCases > 0 ? Number((failedCasesCount / totalCases).toFixed(3)) : 0;

  // Benign cases (expected risk: low)
  const benignCases = caseResults.filter((c) => c.expectedRiskCategory === 'low');
  const totalBenignCases = benignCases.length;
  const determinateBenign = benignCases.filter((c) => !c.isIndeterminate);
  const determinateBenignCases = determinateBenign.length;
  const indeterminateBenign = benignCases.filter((c) => c.isIndeterminate);
  const indeterminateBenignCases = indeterminateBenign.length;
  const falsePositivesCount = caseResults.filter((c) => c.isFalsePositive).length;
  const determinateFalsePositiveRate =
    determinateBenignCases > 0
      ? Number((falsePositivesCount / determinateBenignCases).toFixed(3))
      : 0;
  const totalCorpusFalsePositiveRate =
    totalBenignCases > 0 ? Number((falsePositivesCount / totalBenignCases).toFixed(3)) : 0;
  const falsePositiveRate = determinateFalsePositiveRate;

  // Malicious cases (expected risk: suspicious or high)
  const maliciousCases = caseResults.filter((c) => c.expectedRiskCategory !== 'low');
  const totalMaliciousCases = maliciousCases.length;
  const determinateMalicious = maliciousCases.filter((c) => !c.isIndeterminate);
  const determinateMaliciousCases = determinateMalicious.length;
  const indeterminateMalicious = maliciousCases.filter((c) => c.isIndeterminate);
  const indeterminateMaliciousCases = indeterminateMalicious.length;
  const falseNegativesCount = caseResults.filter((c) => c.isFalseNegative).length;
  const determinateFalseNegativeRate =
    determinateMaliciousCases > 0
      ? Number((falseNegativesCount / determinateMaliciousCases).toFixed(3))
      : 0;
  const totalCorpusFalseNegativeRate =
    totalMaliciousCases > 0 ? Number((falseNegativesCount / totalMaliciousCases).toFixed(3)) : 0;
  const falseNegativeRate = determinateFalseNegativeRate;

  // Indeterminate rates
  const indeterminateCount = caseResults.filter((c) => c.isIndeterminate).length;
  const indeterminateRate = totalCases > 0 ? Number((indeterminateCount / totalCases).toFixed(3)) : 0;
  const benignIndeterminateRate =
    totalBenignCases > 0 ? Number((indeterminateBenignCases / totalBenignCases).toFixed(3)) : 0;
  const maliciousIndeterminateRate =
    totalMaliciousCases > 0 ? Number((indeterminateMaliciousCases / totalMaliciousCases).toFixed(3)) : 0;

  // Failure category breakdown
  const failuresByCategoryType: Record<AdversarialFailureCategory, number> = {
    FALSE_NEGATIVE: 0,
    FALSE_POSITIVE: 0,
    WRONG_SCAM_TYPE: 0,
    MISSED_DNA: 0,
    UNSUPPORTED_EVIDENCE: 0,
    EXTRACTION_FAILURE: 0,
    CONTRADICTORY_FUSION_FAILURE: 0,
    OTHER: 0,
  };

  const failuresBySeverity: Record<FailureSeverity, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };

  let totalFailuresCount = 0;
  let evidenceIntegrityViolationsCount = 0;

  for (const c of caseResults) {
    for (const f of c.failures) {
      totalFailuresCount++;
      failuresByCategoryType[f.category] = (failuresByCategoryType[f.category] || 0) + 1;
      failuresBySeverity[f.severity] = (failuresBySeverity[f.severity] || 0) + 1;
    }
    evidenceIntegrityViolationsCount += c.evidenceIntegrityViolations.length;
  }

  // Scam type accuracy on determinate malicious cases
  const determinateScamCases = caseResults.filter(
    (c) => c.expectedScamType !== 'UNKNOWN' && !c.isIndeterminate
  );
  const correctScamTypeCount = determinateScamCases.filter((c) => c.isScamTypeCorrect).length;
  const scamTypeDeterminateAccuracy =
    determinateScamCases.length > 0
      ? Number((correctScamTypeCount / determinateScamCases.length).toFixed(3))
      : 0;

  // Category breakdown
  const categoryBreakdown: Record<RedTeamTaxonomyCategory, CategoryMetricSummary> = {} as Record<
    RedTeamTaxonomyCategory,
    CategoryMetricSummary
  >;

  for (const cat of RED_TEAM_CATEGORIES) {
    const catCases = caseResults.filter((c) => c.taxonomyCategory === cat);
    const catFailed = catCases.filter((c) => c.hasFailure).length;
    const catFps = catCases.filter((c) => c.isFalsePositive).length;
    const catFns = catCases.filter((c) => c.isFalseNegative).length;
    const catEvi = catCases.reduce((sum, c) => sum + c.evidenceIntegrityViolations.length, 0);
    const catScoreAvg =
      catCases.length > 0
        ? Number((catCases.reduce((sum, c) => sum + c.riskScore, 0) / catCases.length).toFixed(1))
        : 0;

    categoryBreakdown[cat] = {
      category: cat,
      categoryName: RED_TEAM_CATEGORY_NAMES[cat],
      totalCases: catCases.length,
      failedCases: catFailed,
      failureRate: catCases.length > 0 ? Number((catFailed / catCases.length).toFixed(3)) : 0,
      falsePositives: catFps,
      falseNegatives: catFns,
      evidenceViolations: catEvi,
      averageScore: catScoreAvg,
    };
  }

  // Dialect breakdown
  const dialects = Array.from(new Set(caseResults.map((c) => c.dialect)));
  const dialectBreakdown: Record<string, DialectMetricSummary> = {};
  for (const d of dialects) {
    const dCases = caseResults.filter((c) => c.dialect === d);
    const dFailed = dCases.filter((c) => c.hasFailure).length;
    dialectBreakdown[d] = {
      dialect: d,
      totalCases: dCases.length,
      failedCases: dFailed,
      failureRate: dCases.length > 0 ? Number((dFailed / dCases.length).toFixed(3)) : 0,
    };
  }

  // Modality breakdown
  const modalities: AttackModality[] = ['text', 'url', 'text_url', 'screenshot'];
  const modalityBreakdown: Record<string, ModalityMetricSummary> = {};
  for (const m of modalities) {
    const mCases = caseResults.filter((c) => c.modality === m);
    const mFailed = mCases.filter((c) => c.hasFailure).length;
    modalityBreakdown[m] = {
      modality: m,
      totalCases: mCases.length,
      failedCases: mFailed,
      failureRate: mCases.length > 0 ? Number((mFailed / mCases.length).toFixed(3)) : 0,
    };
  }

  // Scam DNA Feature Recall
  const dnaFeatureRecall: DnaFeatureRecallSummary[] = [];
  for (const feature of SCAM_DNA_FEATURES) {
    const casesExpectingFeature = caseResults.filter((c) => c.expectedDnaFeatures.includes(feature));
    const casesDetectingFeature = casesExpectingFeature.filter((c) =>
      c.actualDnaFeatures.includes(feature)
    );
    const recall =
      casesExpectingFeature.length > 0
        ? Number((casesDetectingFeature.length / casesExpectingFeature.length).toFixed(3))
        : null;

    dnaFeatureRecall.push({
      feature,
      expectedCount: casesExpectingFeature.length,
      detectedCount: casesDetectingFeature.length,
      recall,
    });
  }

  // Highest severity failures (Critical & High)
  const highestSeverityFailures = caseResults
    .filter((c) => c.failures.some((f) => f.severity === 'Critical' || f.severity === 'High'))
    .sort((a, b) => {
      const aCrit = a.failures.filter((f) => f.severity === 'Critical').length;
      const bCrit = b.failures.filter((f) => f.severity === 'Critical').length;
      return bCrit - aCrit;
    });

  return {
    version: '1.0.0',
    evaluatedAt: new Date().toISOString(),
    metadata,
    totalCases,
    failedCasesCount,
    overallFailureRate,
    totalBenignCases,
    determinateBenignCases,
    indeterminateBenignCases,
    falsePositivesCount,
    determinateFalsePositiveRate,
    totalCorpusFalsePositiveRate,
    falsePositiveRate,
    totalMaliciousCases,
    determinateMaliciousCases,
    indeterminateMaliciousCases,
    falseNegativesCount,
    determinateFalseNegativeRate,
    totalCorpusFalseNegativeRate,
    falseNegativeRate,
    indeterminateCount,
    indeterminateRate,
    benignIndeterminateRate,
    maliciousIndeterminateRate,
    totalFailuresCount,
    failuresByCategoryType,
    failuresBySeverity,
    evidenceIntegrityViolationsCount,
    scamTypeDeterminateAccuracy,
    scamTypeEvaluatedCases: determinateScamCases.length,
    categoryBreakdown,
    dialectBreakdown,
    modalityBreakdown,
    dnaFeatureRecall,
    highestSeverityFailures,
    caseResults,
  };
}
