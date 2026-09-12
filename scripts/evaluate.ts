/**
 * HARIS (حارس) — Evaluation Harness & Baseline Benchmark Runner
 *
 * Runs the versioned evaluation dataset (evaluation/dataset.ts) through
 * the existing analysis pipeline without modifying production behavior.
 * Computes precision, recall, F1, false positive/negative rates,
 * and per-feature Scam DNA detection statistics.
 */

import * as fs from 'fs';
import * as path from 'path';
import { EVALUATION_DATASET } from '../evaluation/dataset';
import {
  EvaluationCaseResult,
  EvaluationSummary,
  FeatureMetric,
  CategoryMetric,
  DialectMetric,
  EvaluationCategory,
  Dialect,
} from '../evaluation/types';
import { analyzeUnified } from '../lib/vision/pipeline';
import { SCAM_DNA_FEATURES, FeatureKey } from '../lib/analysis/taxonomy';
import { isGeminiConfigured, getConfiguredModel } from '../lib/ai/client';

async function runEvaluation(): Promise<EvaluationSummary> {
  const isAiActive = isGeminiConfigured();
  console.log('='.repeat(70));
  console.log('🛡️  HARIS (حارس) — Evaluation Benchmark Runner (Phase 6A)');
  console.log(`📡 Pipeline Mode: ${isAiActive ? `Hybrid (Deterministic + Gemini AI [${getConfiguredModel()}])` : 'Deterministic Baseline (Offline / Test Mode)'}`);
  console.log(`📊 Dataset Size: ${EVALUATION_DATASET.length} labeled test cases`);
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

  let totalCorrectRisk = 0;
  let totalCorrectScamType = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let screenshotCasesCount = 0;

  // Execute each test case sequentially
  for (let i = 0; i < EVALUATION_DATASET.length; i++) {
    const item = EVALUATION_DATASET[i];
    process.stdout.write(`[${i + 1}/${EVALUATION_DATASET.length}] Evaluating ${item.id}: ${item.title.substring(0, 35)}... `);

    if (item.input.screenshot) {
      screenshotCasesCount++;
    }

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

    const actualRiskCategory = result.riskLevel;
    const actualScamType = result.scamType;
    const actualDnaFeatures = result.scamDna
      .filter((d) => d.detected)
      .map((d) => d.featureId as FeatureKey);

    const isRiskCorrect = actualRiskCategory === item.expectedRiskCategory;
    const isScamTypeCorrect = actualScamType === item.expectedScamType;

    // False Positive: Legitimate message classified as Suspicious or High
    const isFP = item.category === 'legitimate' && (actualRiskCategory === 'suspicious' || actualRiskCategory === 'high');

    // False Negative: Scam message classified as Low
    const isFN = item.category === 'scam' && actualRiskCategory === 'low';

    if (isFP) falsePositives++;
    if (isFN) falseNegatives++;
    if (isRiskCorrect) totalCorrectRisk++;
    if (isScamTypeCorrect) totalCorrectScamType++;

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
      isScamTypeCorrect,
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
      isExtractionFailure: Boolean(result.isExtractionFailure),
      notes: isFP
        ? `⚠️ FALSE POSITIVE: Legitimate flagged as ${actualRiskCategory} (score ${result.riskScore})`
        : isFN
        ? `🚨 FALSE NEGATIVE: Scam missed as low risk (score ${result.riskScore})`
        : !isRiskCorrect
        ? `Mismatch: expected ${item.expectedRiskCategory}, got ${actualRiskCategory} (score ${result.riskScore})`
        : 'OK',
    };

    caseResults.push(caseResult);
    console.log(`${isRiskCorrect ? '✅' : isFP ? '⚠️ FP' : isFN ? '🚨 FN' : '❌'} Score:${result.riskScore} (${elapsed}ms)`);
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
    version: '1.0.0',
    evaluatedAt: new Date().toISOString(),
    environment: {
      geminiConfigured: isAiActive,
      nodeVersion: process.version,
    },
    totalCases,
    scamCases: scamTotal,
    legitimateCases: legitimateTotal,
    ambiguousCases: categoryStats.ambiguous.total,
    screenshotCases: screenshotCasesCount,
    overallAccuracy: Number((totalCorrectRisk / totalCases).toFixed(3)),
    scamTypeAccuracy: Number((totalCorrectScamType / totalCases).toFixed(3)),
    falsePositivesCount: falsePositives,
    falsePositiveRate: Number((legitimateTotal > 0 ? falsePositives / legitimateTotal : 0).toFixed(3)),
    falseNegativesCount: falseNegatives,
    falseNegativeRate: Number((scamTotal > 0 ? falseNegatives / scamTotal : 0).toFixed(3)),
    categoryBreakdown,
    dialectBreakdown,
    featureMetrics,
    caseResults,
  };

  return summary;
}

function generateMarkdownReport(summary: EvaluationSummary): string {
  const failureCases = summary.caseResults.filter((c) => !c.isRiskCategoryCorrect);
  const fpCases = summary.caseResults.filter((c) => c.isFalsePositive);
  const fnCases = summary.caseResults.filter((c) => c.isFalseNegative);

  return `# HARIS (حارس) — Phase 6A Baseline Evaluation Benchmark Report

> **Dataset Version:** ${summary.version}  
> **Evaluation Date:** ${summary.evaluatedAt}  
> **Execution Environment:** Node.js ${summary.environment.nodeVersion} | Gemini Active: ${summary.environment.geminiConfigured ? 'YES' : 'NO (Deterministic Baseline)'}  
> **Total Test Cases:** ${summary.totalCases} (Scams: ${summary.scamCases}, Legitimate: ${summary.legitimateCases}, Ambiguous: ${summary.ambiguousCases}, Screenshots: ${summary.screenshotCases})

---

## 1. Executive Summary & Key Measured Metrics

| Metric | Measured Baseline Value | Target / Benchmark Threshold |
|---|---|---|
| **Overall Classification Accuracy** | **${(summary.overallAccuracy * 100).toFixed(1)}%** (${summary.caseResults.filter((c) => c.isRiskCategoryCorrect).length}/${summary.totalCases}) | > 85.0% |
| **False Positive Rate (FPR)** | **${(summary.falsePositiveRate * 100).toFixed(1)}%** (${summary.falsePositivesCount}/${summary.legitimateCases}) | < 5.0% (Critical for user trust) |
| **False Negative Rate (FNR)** | **${(summary.falseNegativeRate * 100).toFixed(1)}%** (${summary.falseNegativesCount}/${summary.scamCases}) | < 10.0% |
| **Scam Type Classification Accuracy** | **${(summary.scamTypeAccuracy * 100).toFixed(1)}%** | > 70.0% |

> [!IMPORTANT]
> **Measurement Principle:** All metrics above are measured directly from the 70-case labeled evaluation dataset. AI confidence is recorded separately and never conflated with classification probability.

---

## 2. Category Performance Breakdown

| Category | Cases | Correct Risk | Category Accuracy | Average Suspicion Score |
|---|---|---|---|---|
| **Scam / Malicious** | ${summary.categoryBreakdown.scam.total} | ${summary.categoryBreakdown.scam.correctRisk} | **${(summary.categoryBreakdown.scam.accuracy * 100).toFixed(1)}%** | ${summary.categoryBreakdown.scam.averageScore} / 100 |
| **Legitimate / Benign** | ${summary.categoryBreakdown.legitimate.total} | ${summary.categoryBreakdown.legitimate.correctRisk} | **${(summary.categoryBreakdown.legitimate.accuracy * 100).toFixed(1)}%** | ${summary.categoryBreakdown.legitimate.averageScore} / 100 |
| **Ambiguous / Adversarial** | ${summary.categoryBreakdown.ambiguous.total} | ${summary.categoryBreakdown.ambiguous.correctRisk} | **${(summary.categoryBreakdown.ambiguous.accuracy * 100).toFixed(1)}%** | ${summary.categoryBreakdown.ambiguous.averageScore} / 100 |

---

## 3. Dialect & Regional Coverage Breakdown

| Dialect / Variant | Cases | Correct Risk | Dialect Accuracy |
|---|---|---|---|
| **Modern Standard Arabic (MSA)** | ${summary.dialectBreakdown.msa.total} | ${summary.dialectBreakdown.msa.correctRisk} | **${(summary.dialectBreakdown.msa.accuracy * 100).toFixed(1)}%** |
| **Yemeni Arabic & Local Services** | ${summary.dialectBreakdown.yemeni.total} | ${summary.dialectBreakdown.yemeni.correctRisk} | **${(summary.dialectBreakdown.yemeni.accuracy * 100).toFixed(1)}%** |
| **Gulf / Saudi / UAE** | ${summary.dialectBreakdown.gulf.total} | ${summary.dialectBreakdown.gulf.correctRisk} | **${(summary.dialectBreakdown.gulf.accuracy * 100).toFixed(1)}%** |
| **Egyptian Arabic & Local Wallets** | ${summary.dialectBreakdown.egyptian.total} | ${summary.dialectBreakdown.egyptian.correctRisk} | **${(summary.dialectBreakdown.egyptian.accuracy * 100).toFixed(1)}%** |
| **Mixed Arabic + English** | ${summary.dialectBreakdown.mixed_en.total} | ${summary.dialectBreakdown.mixed_en.correctRisk} | **${(summary.dialectBreakdown.mixed_en.accuracy * 100).toFixed(1)}%** |
| **Arabizi (Latin Script)** | ${summary.dialectBreakdown.arabizi.total} | ${summary.dialectBreakdown.arabizi.correctRisk} | **${(summary.dialectBreakdown.arabizi.accuracy * 100).toFixed(1)}%** |

---

## 4. Scam DNA Feature Detection Benchmark

| Scam DNA Feature Key | Ground Truth Count | Detected Count | True Positives | False Positives | False Negatives | Precision | Recall | F1 Score |
|---|---|---|---|---|---|---|---|---|
${summary.featureMetrics
  .map(
    (f) =>
      `| \`${f.featureId}\` | ${f.groundTruthCount} | ${f.detectedCount} | ${f.truePositives} | ${f.falsePositives} | ${f.falseNegatives} | ${(f.precision * 100).toFixed(1)}% | ${(f.recall * 100).toFixed(1)}% | **${(f.f1 * 100).toFixed(1)}%** |`
  )
  .join('\n')}

---

## 5. Failure Case Diagnosis & Baseline Anomalies

Total Mismatches: **${failureCases.length}** / ${summary.totalCases}

### 5.1 False Positives (Legitimate Flagged as Suspicious/High)
${
  fpCases.length === 0
    ? '✅ **Zero False Positives Detected.** The engine strictly avoided flagging any legitimate messages as scams.'
    : fpCases
        .map(
          (c) =>
            `- **[${c.id}] ${c.title}**: Expected \`${c.expectedRiskCategory}\`, got \`${c.actualRiskCategory}\` (Score: ${c.riskScore}). Notes: ${c.notes}`
        )
        .join('\n')
}

### 5.2 False Negatives (Scam Missed as Low Risk)
${
  fnCases.length === 0
    ? '✅ **Zero False Negatives Detected.** All malicious cases were correctly escalated to suspicious or high risk.'
    : fnCases
        .map(
          (c) =>
            `- **[${c.id}] ${c.title}**: Expected \`${c.expectedRiskCategory}\`, got \`${c.actualRiskCategory}\` (Score: ${c.riskScore}). Notes: ${c.notes}`
        )
        .join('\n')
}

### 5.3 Ambiguous & Boundary Calibration Failures
${
  failureCases
    .filter((c) => !c.isFalsePositive && !c.isFalseNegative)
    .map(
      (c) =>
        `- **[${c.id}] ${c.title}** (${c.category}/${c.dialect}): Expected \`${c.expectedRiskCategory}\`, got \`${c.actualRiskCategory}\` (Score: ${c.riskScore}). Expected Type: \`${c.expectedScamType}\`, Actual: \`${c.actualScamType}\`.`
    )
    .join('\n') || 'None.'
}

---

## 6. Recommendations for Phase 6B Red-Team Hardening

1. **Maintain Zero False Positives Guardrail:** Protect negation handling on security warnings (\`"لن يطلب منك OTP"\`).
2. **Refine Borderline Heuristic Thresholds:** Calibrate score contributions on dialectal payment requests without explicit links.
3. **Targeted Red-Team Adversarial Testing:** Execute the 16 attack categories defined in [RED_TEAM_TAXONOMY.md](file:///c:/my_projects/haris/evaluation/RED_TEAM_TAXONOMY.md).
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
  console.log(`   - Overall Classification Accuracy: ${(summary.overallAccuracy * 100).toFixed(1)}% (${summary.totalCases} cases)`);
  console.log(`   - Scam Category Accuracy:         ${(summary.categoryBreakdown.scam.accuracy * 100).toFixed(1)}%`);
  console.log(`   - Legitimate Category Accuracy:   ${(summary.categoryBreakdown.legitimate.accuracy * 100).toFixed(1)}%`);
  console.log(`   - Ambiguous Category Accuracy:    ${(summary.categoryBreakdown.ambiguous.accuracy * 100).toFixed(1)}%`);
  console.log(`   - False Positive Rate:            ${(summary.falsePositiveRate * 100).toFixed(1)}% (${summary.falsePositivesCount}/${summary.legitimateCases})`);
  console.log(`   - False Negative Rate:            ${(summary.falseNegativeRate * 100).toFixed(1)}% (${summary.falseNegativesCount}/${summary.scamCases})`);
  console.log(`   - Scam-Type Classification:       ${(summary.scamTypeAccuracy * 100).toFixed(1)}%`);
  console.log('='.repeat(70));
}

main().catch((err) => {
  console.error('Fatal Evaluation Error:', err);
  process.exit(1);
});
