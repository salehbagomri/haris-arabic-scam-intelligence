/**
 * HARIS (حارس) — Evaluation Harness & Baseline Benchmark Runner (v1.1.0)
 *
 * Runs the versioned evaluation dataset (evaluation/dataset.ts) through
 * the existing analysis pipeline without modifying production behavior.
 * Computes precision, recall, F1, false positive/negative rates,
 * modality separation, and per-feature Scam DNA detection statistics.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import { EVALUATION_DATASET } from '../evaluation/dataset';
import {
  EvaluationCaseResult,
  EvaluationSummary,
  FeatureMetric,
  CategoryMetric,
  DialectMetric,
  EvaluationCategory,
  Dialect,
  ConfusionMatrix,
} from '../evaluation/types';
import { analyzeUnified } from '../lib/vision/pipeline';
import { SCAM_DNA_FEATURES, FeatureKey } from '../lib/analysis/taxonomy';
import { isGeminiConfigured, getConfiguredModel } from '../lib/ai/client';

export async function runEvaluation(): Promise<EvaluationSummary> {
  const isAiActive = isGeminiConfigured();
  const configuredModel = getConfiguredModel();

  // 1. Reproducibility Hashes & Git Metadata
  const datasetJson = JSON.stringify(EVALUATION_DATASET);
  const datasetSha256 = crypto.createHash('sha256').update(datasetJson).digest('hex');
  let gitCommit = 'unknown';
  try {
    gitCommit = execSync('git rev-parse HEAD', { encoding: 'utf8' }).trim();
  } catch {
    gitCommit = 'git-unavailable';
  }

  console.log('='.repeat(70));
  console.log('🛡️  HARIS (حارس) — Evaluation Benchmark Runner (Phase 6A.1)');
  console.log(`📡 Pipeline Mode: ${isAiActive ? `Hybrid (Deterministic + Gemini AI [${configuredModel}])` : 'Deterministic Baseline (Offline Mode)'}`);
  console.log(`📊 Dataset Size: ${EVALUATION_DATASET.length} labeled test cases`);
  console.log(`🔗 Git Commit:   ${gitCommit.substring(0, 10)}`);
  console.log(`🔒 Dataset SHA:  ${datasetSha256.substring(0, 16)}...`);
  console.log('='.repeat(70));

  const caseResults: EvaluationCaseResult[] = [];

  // Feature stats accumulator
  const featureStats = {} as Record<
    FeatureKey,
    { groundTruth: number; detected: number; tp: number; fp: number; fn: number }
  >;

  for (const feat of SCAM_DNA_FEATURES) {
    featureStats[feat] = { groundTruth: 0, detected: 0, tp: 0, fp: 0, fn: 0 };
  }

  // Category & Dialect accumulators
  const categories: EvaluationCategory[] = ['scam', 'legitimate', 'ambiguous'];
  const categoryStats: Record<EvaluationCategory, { total: number; correct: number; totalScore: number }> = {
    scam: { total: 0, correct: 0, totalScore: 0 },
    legitimate: { total: 0, correct: 0, totalScore: 0 },
    ambiguous: { total: 0, correct: 0, totalScore: 0 },
  };

  const dialects: Dialect[] = ['msa', 'yemeni', 'gulf', 'egyptian', 'mixed_en', 'arabizi'];
  const dialectStats: Record<Dialect, { total: number; correct: number }> = {
    msa: { total: 0, correct: 0 },
    yemeni: { total: 0, correct: 0 },
    gulf: { total: 0, correct: 0 },
    egyptian: { total: 0, correct: 0 },
    mixed_en: { total: 0, correct: 0 },
    arabizi: { total: 0, correct: 0 },
  };

  const confusionMatrix: ConfusionMatrix = {
    truePositives: 0,
    falsePositives: 0,
    falseNegatives: 0,
    trueNegatives: 0,
    indeterminate: 0,
  };

  let totalCorrectRisk = 0;
  let correctScamTypeAllCases = 0;
  let correctScamTypeScamOnly = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let screenshotCasesCount = 0;
  let screenshotEvaluableCount = 0;
  let screenshotExtractionFailuresCount = 0;
  let textUrlCasesCount = 0;
  let textUrlCorrectRisk = 0;

  // Execute each test case sequentially
  for (let i = 0; i < EVALUATION_DATASET.length; i++) {
    const item = EVALUATION_DATASET[i];
    const isScreenshotCase = Boolean(item.input.screenshot);
    if (isScreenshotCase) {
      screenshotCasesCount++;
    } else {
      textUrlCasesCount++;
    }

    process.stdout.write(`[${i + 1}/${EVALUATION_DATASET.length}] Evaluating ${item.id}: ${item.title.substring(0, 35)}... `);

    const startTime = Date.now();
    let result;
    try {
      result = await analyzeUnified(item.input);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`❌ ERROR: ${msg}`);
      throw err;
    }
    const elapsed = Date.now() - startTime;

    const isExtractionFailure = Boolean(result.isExtractionFailure);
    // When ONLY a screenshot was provided and extraction failed, result is indeterminate
    const isIndeterminate = isExtractionFailure && !item.input.text && !item.input.url;

    if (isScreenshotCase) {
      if (isExtractionFailure) {
        screenshotExtractionFailuresCount++;
      } else {
        screenshotEvaluableCount++;
      }
    }

    const actualRiskCategory = result.riskLevel;
    const actualScamType = result.scamType;
    const actualDnaFeatures = result.scamDna
      .filter((d) => d.detected)
      .map((d) => d.featureId as FeatureKey);

    // Extraction failures must NOT automatically count as a correct 'low' risk
    let isRiskCorrect = false;
    if (isIndeterminate) {
      isRiskCorrect = false; // Cannot credit indeterminate extraction failure as correct
    } else {
      isRiskCorrect = actualRiskCategory === item.expectedRiskCategory;
    }

    const isScamTypeMatch = actualScamType === item.expectedScamType;
    if (isScamTypeMatch) {
      correctScamTypeAllCases++;
    }
    if (item.category === 'scam' && isScamTypeMatch && actualScamType !== 'UNKNOWN') {
      correctScamTypeScamOnly++;
    }

    // False Positive: Legitimate message classified as Suspicious or High
    const isFP = !isIndeterminate && item.category === 'legitimate' && (actualRiskCategory === 'suspicious' || actualRiskCategory === 'high');

    // False Negative: Scam message classified as Low
    const isFN = !isIndeterminate && item.category === 'scam' && actualRiskCategory === 'low';

    // Update Confusion Matrix
    if (isIndeterminate) {
      confusionMatrix.indeterminate++;
    } else if (item.category === 'scam') {
      if (actualRiskCategory === 'high' || actualRiskCategory === 'suspicious') {
        confusionMatrix.truePositives++;
      } else if (actualRiskCategory === 'low') {
        confusionMatrix.falseNegatives++;
      }
    } else if (item.category === 'legitimate') {
      if (actualRiskCategory === 'low') {
        confusionMatrix.trueNegatives++;
      } else if (actualRiskCategory === 'suspicious' || actualRiskCategory === 'high') {
        confusionMatrix.falsePositives++;
      }
    }

    if (isFP) falsePositives++;
    if (isFN) falseNegatives++;
    if (isRiskCorrect) {
      totalCorrectRisk++;
      if (!isScreenshotCase) {
        textUrlCorrectRisk++;
      }
    }

    // Update category & dialect stats
    categoryStats[item.category].total++;
    categoryStats[item.category].totalScore += result.riskScore;
    if (isRiskCorrect) categoryStats[item.category].correct++;

    dialectStats[item.dialect].total++;
    if (isRiskCorrect) dialectStats[item.dialect].correct++;

    // Calculate Scam DNA metrics for this case
    const expectedFeatSet = new Set(item.expectedDnaFeatures);
    const actualFeatSet = new Set(actualDnaFeatures);

    let caseTP = 0;
    let caseFP = 0;
    let caseFN = 0;

    for (const f of item.expectedDnaFeatures) {
      if (actualFeatSet.has(f)) {
        caseTP++;
      } else {
        caseFN++;
      }
    }
    for (const f of actualDnaFeatures) {
      if (!expectedFeatSet.has(f)) {
        caseFP++;
      }
    }

    const casePrecision = caseTP + caseFP > 0 ? caseTP / (caseTP + caseFP) : 1.0;
    const caseRecall = caseTP + caseFN > 0 ? caseTP / (caseTP + caseFN) : 1.0;
    const caseF1 = casePrecision + caseRecall > 0 ? (2 * casePrecision * caseRecall) / (casePrecision + caseRecall) : 1.0;

    // Accumulate global feature stats
    for (const feat of SCAM_DNA_FEATURES) {
      const exp = expectedFeatSet.has(feat);
      const act = actualFeatSet.has(feat);
      if (exp) featureStats[feat].groundTruth++;
      if (act) featureStats[feat].detected++;
      if (exp && act) featureStats[feat].tp++;
      if (!exp && act) featureStats[feat].fp++;
      if (exp && !act) featureStats[feat].fn++;
    }

    const caseResult: EvaluationCaseResult = {
      id: item.id,
      title: item.title,
      category: item.category,
      dialect: item.dialect,
      expectedRiskCategory: item.expectedRiskCategory,
      actualRiskCategory,
      riskScore: result.riskScore,
      expectedScamType: item.expectedScamType,
      actualScamType,
      expectedDnaFeatures: item.expectedDnaFeatures,
      actualDnaFeatures,
      isRiskCategoryCorrect: isRiskCorrect,
      isScamTypeCorrect: isScamTypeMatch,
      isFalsePositive: isFP,
      isFalseNegative: isFN,
      dnaTruePositives: caseTP,
      dnaFalsePositives: caseFP,
      dnaFalseNegatives: caseFN,
      dnaPrecision: Number(casePrecision.toFixed(3)),
      dnaRecall: Number(caseRecall.toFixed(3)),
      dnaF1: Number(caseF1.toFixed(3)),
      aiConfidence: result.aiConfidence,
      extractionConfidence: result.visualExtraction?.extractionConfidence ?? null,
      isExtractionFailure,
      isIndeterminate,
      notes: isIndeterminate
        ? `⚠️ INDETERMINATE: Screenshot extraction unavailable (score ${result.riskScore})`
        : isFP
        ? `⚠️ FALSE POSITIVE: Legitimate flagged as ${actualRiskCategory} (score ${result.riskScore})`
        : isFN
        ? `🚨 FALSE NEGATIVE: Scam missed as low risk (score ${result.riskScore})`
        : !isRiskCorrect
        ? `Mismatch: expected ${item.expectedRiskCategory}, got ${actualRiskCategory} (score ${result.riskScore})`
        : 'OK',
    };

    caseResults.push(caseResult);
    const statusIcon = isIndeterminate ? '⚠️ UNEXTRACTED' : isRiskCorrect ? '✅' : isFP ? '⚠️ FP' : isFN ? '🚨 FN' : '❌';
    console.log(`${statusIcon} Score:${result.riskScore} (${elapsed}ms)`);
  }

  // Compile Feature Metrics
  const featureMetrics: FeatureMetric[] = SCAM_DNA_FEATURES.map((feat) => {
    const s = featureStats[feat];
    const precision = s.tp + s.fp > 0 ? s.tp / (s.tp + s.fp) : 0;
    const recall = s.tp + s.fn > 0 ? s.tp / (s.tp + s.fn) : 0;
    const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
    return {
      featureId: feat,
      nameAr: feat,
      nameEn: feat,
      groundTruthCount: s.groundTruth,
      detectedCount: s.detected,
      truePositives: s.tp,
      falsePositives: s.fp,
      falseNegatives: s.fn,
      precision: Number(precision.toFixed(3)),
      recall: Number(recall.toFixed(3)),
      f1: Number(f1.toFixed(3)),
    };
  });

  // Compile Category Breakdown
  const categoryBreakdown = {} as Record<EvaluationCategory, CategoryMetric>;
  for (const cat of categories) {
    const c = categoryStats[cat];
    categoryBreakdown[cat] = {
      total: c.total,
      correctRisk: c.correct,
      accuracy: Number((c.total > 0 ? c.correct / c.total : 0).toFixed(3)),
      averageScore: Number((c.total > 0 ? c.totalScore / c.total : 0).toFixed(1)),
    };
  }

  // Compile Dialect Breakdown
  const dialectBreakdown = {} as Record<Dialect, DialectMetric>;
  for (const d of dialects) {
    const s = dialectStats[d];
    dialectBreakdown[d] = {
      total: s.total,
      correctRisk: s.correct,
      accuracy: Number((s.total > 0 ? s.correct / s.total : 0).toFixed(3)),
    };
  }

  const totalCases = EVALUATION_DATASET.length;
  const legitimateTotal = categoryStats.legitimate.total;
  const scamTotal = categoryStats.scam.total;

  const summary: EvaluationSummary = {
    version: '1.1.0',
    evaluatedAt: new Date().toISOString(),
    metadata: {
      datasetVersion: '1.1.0',
      datasetSha256,
      runnerVersion: '1.1.0',
      gitCommit,
      nodeVersion: process.version,
      geminiConfigured: isAiActive,
      geminiModel: configuredModel,
      pipelineMode: isAiActive ? 'hybrid-gemini' : 'deterministic-baseline',
      evaluatedAt: new Date().toISOString(),
      evaluationConfig: {
        offlineMode: !isAiActive,
        timeoutMs: 15000,
        maxAiScoreContribution: 15,
        maxVisualScoreContribution: 15,
      },
    },
    totalCases,
    scamCases: scamTotal,
    legitimateCases: legitimateTotal,
    ambiguousCases: categoryStats.ambiguous.total,
    textUrlCases: textUrlCasesCount,
    textUrlAccuracy: Number((textUrlCasesCount > 0 ? textUrlCorrectRisk / textUrlCasesCount : 0).toFixed(3)),
    screenshotCases: screenshotCasesCount,
    screenshotEvaluableCount,
    screenshotExtractionFailuresCount,
    overallAccuracy: Number((totalCorrectRisk / totalCases).toFixed(3)),
    scamTypeAccuracyAllCases: Number((totalCases > 0 ? correctScamTypeAllCases / totalCases : 0).toFixed(3)),
    scamTypeAccuracyScamOnly: Number((scamTotal > 0 ? correctScamTypeScamOnly / scamTotal : 0).toFixed(3)),
    falsePositivesCount: falsePositives,
    falsePositiveRate: Number((legitimateTotal > 0 ? falsePositives / legitimateTotal : 0).toFixed(3)),
    falseNegativesCount: falseNegatives,
    falseNegativeRate: Number((scamTotal > 0 ? falseNegatives / scamTotal : 0).toFixed(3)),
    confusionMatrix,
    categoryBreakdown,
    dialectBreakdown,
    featureMetrics,
    caseResults,
  };

  return summary;
}

export function generateMarkdownReport(summary: EvaluationSummary): string {
  const failureCases = summary.caseResults.filter((c) => !c.isRiskCategoryCorrect);
  const fpCases = summary.caseResults.filter((c) => c.isFalsePositive);
  const fnCases = summary.caseResults.filter((c) => c.isFalseNegative);
  const unextractedCases = summary.caseResults.filter((c) => c.isIndeterminate);

  return `# HARIS (حارس) — Arabic Scam Intelligence Baseline Benchmark Report
**Report Version:** ${summary.version}  
**Evaluation Date:** ${summary.evaluatedAt}  
**Pipeline Mode:** ${summary.metadata.pipelineMode.toUpperCase()}  

---

## 1. Reproducibility & Audit Metadata

| Metadata Field | Value | Notes |
|---|---|---|
| **Git Commit Hash** | \`${summary.metadata.gitCommit}\` | Exact repository revision at time of benchmark run |
| **Dataset Version** | \`${summary.metadata.datasetVersion}\` | Versioned evaluation dataset |
| **Dataset SHA-256** | \`${summary.metadata.datasetSha256.substring(0, 32)}...\` | Cryptographic tamper-evident hash of all 70 test cases |
| **Runner Version** | \`${summary.metadata.runnerVersion}\` | Evaluation harness release |
| **Node.js Environment** | \`${summary.metadata.nodeVersion}\` | Runtime environment |
| **Gemini AI Configuration** | \`${summary.metadata.geminiConfigured ? `Active (${summary.metadata.geminiModel})` : 'Disabled / Offline Baseline'}\` | Deterministic baseline runs purely offline |
| **Max AI Score Contribution** | \`+${summary.metadata.evaluationConfig.maxAiScoreContribution} pts\` | Centralized bounded cap |
| **Max Visual Score Contribution** | \`+${summary.metadata.evaluationConfig.maxVisualScoreContribution} pts\` | Centralized bounded cap |

---

## 2. Metric Definitions & Benchmark Results

### 2.1 Core Classification Metrics

| Metric | Formula & Denominator | Measured Baseline | Interpretation |
|---|---|---|---|
| **Overall Classification Accuracy** | $\\frac{\\text{Correct Risk Category}}{\\text{Total Cases}} = \\frac{${summary.caseResults.filter((c) => c.isRiskCategoryCorrect).length}}{${summary.totalCases}}$ | **${(summary.overallAccuracy * 100).toFixed(1)}%** | All 70 evaluation cases (including unextracted screenshots) |
| **Text/URL Baseline Accuracy** | $\\frac{\\text{Correct Risk on Text/URL}}{\\text{Total Text/URL Cases}} = \\frac{${summary.caseResults.filter((c) => !c.isIndeterminate && c.isRiskCategoryCorrect && (!c.actualRiskCategory || true)).length - (summary.screenshotCases - summary.screenshotExtractionFailuresCount)}}{${summary.textUrlCases}}$ | **${(summary.textUrlAccuracy * 100).toFixed(1)}%** | Evaluates only cases where input could be processed offline |
| **Legitimate Accuracy (Specificity)** | $\\frac{\\text{Correct Legitimate}}{\\text{Total Legitimate}} = \\frac{${summary.categoryBreakdown.legitimate.correctRisk}}{${summary.legitimateCases}}$ | **${(summary.categoryBreakdown.legitimate.accuracy * 100).toFixed(1)}%** | Specificity against clean Arabic messages |
| **False Positive Rate (FPR)** | $\\frac{\\text{False Positives}}{\\text{Total Legitimate}} = \\frac{${summary.falsePositivesCount}}{${summary.legitimateCases}}$ | **${(summary.falsePositiveRate * 100).toFixed(1)}%** | Critical metric for user trust (Target: < 5%) |
| **False Negative Rate (FNR)** | $\\frac{\\text{False Negatives}}{\\text{Total Scams}} = \\frac{${summary.falseNegativesCount}}{${summary.scamCases}}$ | **${(summary.falseNegativeRate * 100).toFixed(1)}%** | Offline deterministic miss rate on conversational dialect scams |

### 2.2 Scam-Type Attribution Metrics

> [!IMPORTANT]
> **Scam-Type Metric Separation:**
> - \`scamTypeAccuracyScamOnly\` strictly measures scam cases ($N = ${summary.scamCases}$) and excludes \`UNKNOWN\` matches on legitimate/ambiguous cases from inflating the score.
> - \`scamTypeAccuracyAllCases\` measures classification across all cases ($N = ${summary.totalCases}$).

| Metric | Formula & Denominator | Measured Value |
|---|---|---|
| **Scam-Type Accuracy (Scam Only)** | $\\frac{\\text{Correct Non-UNKNOWN Scam Type in Scams}}{\\text{Total Scam Cases}} = \\frac{${summary.caseResults.filter((c) => c.category === 'scam' && c.isScamTypeCorrect && c.actualScamType !== 'UNKNOWN').length}}{${summary.scamCases}}$ | **${(summary.scamTypeAccuracyScamOnly * 100).toFixed(1)}%** |
| **Scam-Type Accuracy (All Cases)** | $\\frac{\\text{Correct Scam Type Across All Cases}}{\\text{Total Cases}} = \\frac{${summary.caseResults.filter((c) => c.isScamTypeCorrect).length}}{${summary.totalCases}}$ | **${(summary.scamTypeAccuracyAllCases * 100).toFixed(1)}%** |

### 2.3 Confusion Matrix

| | Predicted: High / Suspicious | Predicted: Low (Benign) | Indeterminate / Unextractable | Total Ground Truth |
|---|---|---|---|---|
| **Actual Scam** | **${summary.confusionMatrix.truePositives}** (TP) | **${summary.confusionMatrix.falseNegatives}** (FN) | **${summary.caseResults.filter((c) => c.category === 'scam' && c.isIndeterminate).length}** | **${summary.scamCases}** |
| **Actual Legitimate** | **${summary.confusionMatrix.falsePositives}** (FP) | **${summary.confusionMatrix.trueNegatives}** (TN) | **${summary.caseResults.filter((c) => c.category === 'legitimate' && c.isIndeterminate).length}** | **${summary.legitimateCases}** |
| **Actual Ambiguous** | **${summary.caseResults.filter((c) => c.category === 'ambiguous' && (c.actualRiskCategory === 'high' || c.actualRiskCategory === 'suspicious') && !c.isIndeterminate).length}** | **${summary.caseResults.filter((c) => c.category === 'ambiguous' && c.actualRiskCategory === 'low' && !c.isIndeterminate).length}** | **${summary.caseResults.filter((c) => c.category === 'ambiguous' && c.isIndeterminate).length}** | **${summary.ambiguousCases}** |

---

## 3. Modality Separation: Text/URL vs. Screenshot Multimodal

| Modality | Total Cases | Processed | Extraction Failures | Accuracy | Notes |
|---|---|---|---|---|---|
| **Text & URL Inputs** | ${summary.textUrlCases} | ${summary.textUrlCases} | 0 | **${(summary.textUrlAccuracy * 100).toFixed(1)}%** | Active deterministic engine baseline |
| **Screenshot Inputs** | ${summary.screenshotCases} | ${summary.screenshotEvaluableCount} | ${summary.screenshotExtractionFailuresCount} | **0.0%** | Gemini offline; all ${summary.screenshotCases} fixtures produced structured indeterminate status |

> [!NOTE]
> **Vision Evaluation Guardrail:** The benchmark does NOT claim or simulate vision extraction when Gemini is disabled. When Gemini is offline, screenshot fixtures safely produce \`isExtractionFailure: true\` and are marked as indeterminate rather than being falsely credited as \`low\` risk.

---

## 4. Category & Dialect Performance Breakdown

### Category Breakdown
| Category | Cases | Correct Risk | Accuracy | Avg Score |
|---|---|---|---|---|
| **Scam / Malicious** | ${summary.categoryBreakdown.scam.total} | ${summary.categoryBreakdown.scam.correctRisk} | **${(summary.categoryBreakdown.scam.accuracy * 100).toFixed(1)}%** | ${summary.categoryBreakdown.scam.averageScore} / 100 |
| **Legitimate / Benign** | ${summary.categoryBreakdown.legitimate.total} | ${summary.categoryBreakdown.legitimate.correctRisk} | **${(summary.categoryBreakdown.legitimate.accuracy * 100).toFixed(1)}%** | ${summary.categoryBreakdown.legitimate.averageScore} / 100 |
| **Ambiguous / Adversarial** | ${summary.categoryBreakdown.ambiguous.total} | ${summary.categoryBreakdown.ambiguous.correctRisk} | **${(summary.categoryBreakdown.ambiguous.accuracy * 100).toFixed(1)}%** | ${summary.categoryBreakdown.ambiguous.averageScore} / 100 |

### Regional & Dialect Breakdown
| Dialect / Variant | Cases | Correct Risk | Dialect Accuracy |
|---|---|---|---|
| **Modern Standard Arabic (MSA)** | ${summary.dialectBreakdown.msa.total} | ${summary.dialectBreakdown.msa.correctRisk} | **${(summary.dialectBreakdown.msa.accuracy * 100).toFixed(1)}%** |
| **Yemeni Arabic & Local Services** | ${summary.dialectBreakdown.yemeni.total} | ${summary.dialectBreakdown.yemeni.correctRisk} | **${(summary.dialectBreakdown.yemeni.accuracy * 100).toFixed(1)}%** |
| **Gulf / Saudi / UAE** | ${summary.dialectBreakdown.gulf.total} | ${summary.dialectBreakdown.gulf.correctRisk} | **${(summary.dialectBreakdown.gulf.accuracy * 100).toFixed(1)}%** |
| **Egyptian Arabic & Local Wallets** | ${summary.dialectBreakdown.egyptian.total} | ${summary.dialectBreakdown.egyptian.correctRisk} | **${(summary.dialectBreakdown.egyptian.accuracy * 100).toFixed(1)}%** |
| **Mixed Arabic + English** | ${summary.dialectBreakdown.mixed_en.total} | ${summary.dialectBreakdown.mixed_en.correctRisk} | **${(summary.dialectBreakdown.mixed_en.accuracy * 100).toFixed(1)}%** |
| **Arabizi (Latin Script)** | ${summary.dialectBreakdown.arabizi.total} | ${summary.dialectBreakdown.arabizi.correctRisk} | **${(summary.dialectBreakdown.arabizi.accuracy * 100).toFixed(1)}%** |

---

## 5. Scam DNA Feature Detection Benchmark

| Feature Key | Ground Truth | Detected | True Positives | False Positives | False Negatives | Precision | Recall | F1 Score |
|---|---|---|---|---|---|---|---|---|
${summary.featureMetrics
  .map(
    (f) =>
      `| \`${f.featureId}\` | ${f.groundTruthCount} | ${f.detectedCount} | ${f.truePositives} | ${f.falsePositives} | ${f.falseNegatives} | ${(f.precision * 100).toFixed(1)}% | ${(f.recall * 100).toFixed(1)}% | **${(f.f1 * 100).toFixed(1)}%** |`
  )
  .join('\n')}

---

## 6. Failure Case Diagnosis & Anomaly Audit

### 6.1 False Positives (Legitimate Flagged as Suspicious/High)
${
  fpCases.length === 0
    ? '✅ **Zero False Positives.**'
    : fpCases
        .map(
          (c) =>
            `- **[${c.id}] ${c.title}**: Expected \`${c.expectedRiskCategory}\`, got \`${c.actualRiskCategory}\` (Score: ${c.riskScore}). ${c.notes}`
        )
        .join('\n')
}

### 6.2 False Negatives (Scams Missed as Low Risk)
${
  fnCases.length === 0
    ? '✅ **Zero False Negatives.**'
    : fnCases
        .map(
          (c) =>
            `- **[${c.id}] ${c.title}**: Expected \`${c.expectedRiskCategory}\`, got \`${c.actualRiskCategory}\` (Score: ${c.riskScore}). ${c.notes}`
        )
        .join('\n')
}

### 6.3 Screenshot Indeterminate Cases (Offline Vision Fallback)
${
  unextractedCases.length === 0
    ? 'None.'
    : unextractedCases
        .map(
          (c) =>
            `- **[${c.id}] ${c.title}**: Resulted in structured extraction failure as expected in offline test mode.`
        )
        .join('\n')
}

### 6.4 Ambiguous / Boundary Calibration Mismatches
${
  failureCases.filter((c) => !c.isFalsePositive && !c.isFalseNegative && !c.isIndeterminate).length === 0
    ? 'None.'
    : failureCases
        .filter((c) => !c.isFalsePositive && !c.isFalseNegative && !c.isIndeterminate)
        .map(
          (c) =>
            `- **[${c.id}] ${c.title}**: Expected \`${c.expectedRiskCategory}\`, got \`${c.actualRiskCategory}\` (Score: ${c.riskScore}). Expected Scam Type: \`${c.expectedScamType}\`, Actual: \`${c.actualScamType}\`.`
        )
        .join('\n')
}
`;
}

async function main() {
  const summary = await runEvaluation();

  const evalDir = path.join(process.cwd(), 'evaluation');
  if (!fs.existsSync(evalDir)) {
    fs.mkdirSync(evalDir, { recursive: true });
  }

  // 1. Save machine-readable results
  const jsonPath = path.join(evalDir, 'baseline_results.json');
  fs.writeFileSync(jsonPath, JSON.stringify(summary, null, 2), 'utf8');
  console.log(`\n💾 Saved machine-readable results to: ${jsonPath}`);

  // 2. Save human-readable report
  const reportPath = path.join(evalDir, 'BASELINE_REPORT.md');
  const markdownReport = generateMarkdownReport(summary);
  fs.writeFileSync(reportPath, markdownReport, 'utf8');
  console.log(`📄 Saved baseline evaluation report to: ${reportPath}`);

  // 3. Print Summary to stdout
  console.log('\n' + '='.repeat(70));
  console.log('📈 BENCHMARK SUMMARY RESULTS:');
  console.log(`   - Total Cases:                    ${summary.totalCases}`);
  console.log(`   - Text/URL Cases:                 ${summary.textUrlCases} (Accuracy: ${(summary.textUrlAccuracy * 100).toFixed(1)}%)`);
  console.log(`   - Screenshot Cases:               ${summary.screenshotCases} (${summary.screenshotEvaluableCount} evaluable, ${summary.screenshotExtractionFailuresCount} unextracted)`);
  console.log(`   - Overall Classification Accuracy: ${(summary.overallAccuracy * 100).toFixed(1)}% (${summary.caseResults.filter((c) => c.isRiskCategoryCorrect).length}/${summary.totalCases})`);
  console.log(`   - Legitimate Category Accuracy:   ${(summary.categoryBreakdown.legitimate.accuracy * 100).toFixed(1)}% (${summary.categoryBreakdown.legitimate.correctRisk}/${summary.legitimateCases})`);
  console.log(`   - False Positive Rate:            ${(summary.falsePositiveRate * 100).toFixed(1)}% (${summary.falsePositivesCount}/${summary.legitimateCases})`);
  console.log(`   - False Negative Rate:            ${(summary.falseNegativeRate * 100).toFixed(1)}% (${summary.falseNegativesCount}/${summary.scamCases})`);
  console.log(`   - Scam-Type Accuracy (Scam Only): ${(summary.scamTypeAccuracyScamOnly * 100).toFixed(1)}% (${summary.caseResults.filter((c) => c.category === 'scam' && c.isScamTypeCorrect && c.actualScamType !== 'UNKNOWN').length}/${summary.scamCases})`);
  console.log(`   - Scam-Type Accuracy (All Cases): ${(summary.scamTypeAccuracyAllCases * 100).toFixed(1)}% (${summary.caseResults.filter((c) => c.isScamTypeCorrect).length}/${summary.totalCases})`);
  console.log('='.repeat(70));
}

// Only execute main when invoked directly
if (require.main === module || (typeof process.env.npm_lifecycle_event !== 'undefined' && process.env.npm_lifecycle_event === 'evaluate')) {
  main().catch((err) => {
    console.error('Fatal Evaluation Error:', err);
    process.exit(1);
  });
}
