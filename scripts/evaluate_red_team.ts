/**
 * HARIS (حارس) — Adversarial Red-Team Benchmark Runner (v1.0.0 — Phase 6B)
 *
 * Executes the full 48-case Red-Team adversarial corpus against the production
 * analysis pipeline, evaluates all 16 threat categories, detects evidence integrity
 * violations, saves red_team_results.json, and generates RED_TEAM_REPORT.md.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import { RED_TEAM_DATASET } from '../evaluation/red_team/dataset';
import { evaluateRedTeamItem, calculateRedTeamSummary } from '../evaluation/red_team/evaluator';
import { RedTeamCaseResult, RedTeamBenchmarkSummary } from '../evaluation/red_team/types';

function getGitCommit(): string {
  try {
    return execSync('git rev-parse HEAD', { encoding: 'utf-8' }).trim();
  } catch {
    return 'unknown-commit';
  }
}

async function runRedTeamEvaluation() {
  console.log('======================================================================');
  console.log('🛡️  HARIS (حارس) — Adversarial Red-Team Benchmark Runner (Phase 6B)');
  console.log('======================================================================');

  const gitCommit = getGitCommit();
  const datasetJson = JSON.stringify(RED_TEAM_DATASET);
  const datasetSha256 = crypto.createHash('sha256').update(datasetJson).digest('hex');

  console.log(`📌 Git Commit:    ${gitCommit.substring(0, 10)}...`);
  console.log(`🔒 Dataset SHA:   ${datasetSha256.substring(0, 16)}...`);
  console.log(`📊 Total Attacks: ${RED_TEAM_DATASET.length} cases (16 categories × 3 cases)`);
  console.log(`⏱️  Started At:    ${new Date().toISOString()}`);
  console.log('----------------------------------------------------------------------\n');

  const caseResults: RedTeamCaseResult[] = [];
  let index = 0;

  for (const item of RED_TEAM_DATASET) {
    index++;
    const startTime = Date.now();
    const result = await evaluateRedTeamItem(item);
    const durationMs = Date.now() - startTime;
    caseResults.push(result);

    let statusEmoji = '✅';
    if (result.isFalseNegative) statusEmoji = '🚨 FN';
    else if (result.isFalsePositive) statusEmoji = '⚠️ FP';
    else if (result.isIndeterminate) statusEmoji = '⚠️ UNEXTRACTED';
    else if (result.hasFailure) statusEmoji = '❌ FAIL';

    const truncatedTitle = item.title.length > 38 ? item.title.substring(0, 38) + '...' : item.title.padEnd(41);
    console.log(
      `[${index.toString().padStart(2, '0')}/${RED_TEAM_DATASET.length}] Evaluating ${item.id}: ${truncatedTitle} ${statusEmoji} Score:${result.riskScore} (${durationMs}ms)`
    );
  }

  const metadata = {
    datasetVersion: '1.0.0',
    datasetSha256,
    runnerVersion: '1.0.0',
    evaluationSourceCommit: gitCommit,
    nodeVersion: process.version,
    pipelineMode: 'deterministic-baseline-redteam',
    geminiConfigured: Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.trim().length > 0),
  };

  const summary = calculateRedTeamSummary(caseResults, metadata);

  // Save machine-readable JSON results
  const resultsJsonPath = path.join(process.cwd(), 'evaluation', 'red_team_results.json');
  fs.writeFileSync(resultsJsonPath, JSON.stringify(summary, null, 2), 'utf-8');
  console.log(`\n💾 Saved red-team results to: ${resultsJsonPath}`);

  // Generate Markdown report
  const markdownReport = generateMarkdownReport(summary);
  const reportPath = path.join(process.cwd(), 'evaluation', 'RED_TEAM_REPORT.md');
  fs.writeFileSync(reportPath, markdownReport, 'utf-8');
  console.log(`📄 Saved Red-Team evaluation report to: ${reportPath}`);

  // Print Summary Table to Terminal
  console.log('\n======================================================================');
  console.log('📈 RED-TEAM ADVERSARIAL BENCHMARK SUMMARY (Phase 6B.1):');
  console.log(`   - Total Attack Cases:                     ${summary.totalCases}`);
  console.log(`   - Case-Level Failure Count:               ${summary.failedCasesCount}/${summary.totalCases} (${(summary.overallFailureRate * 100).toFixed(1)}%)`);
  console.log(`   - Cumulative Defect Instances:            ${summary.totalFailuresCount}`);
  console.log(`   - Determinate False Positive Rate (FPR):   ${(summary.determinateFalsePositiveRate * 100).toFixed(1)}% (${summary.falsePositivesCount}/${summary.determinateBenignCases}) [Total-Corpus: ${(summary.totalCorpusFalsePositiveRate * 100).toFixed(1)}% (${summary.falsePositivesCount}/${summary.totalBenignCases})]`);
  console.log(`   - Determinate False Negative Rate (FNR):   ${(summary.determinateFalseNegativeRate * 100).toFixed(1)}% (${summary.falseNegativesCount}/${summary.determinateMaliciousCases}) [Total-Corpus: ${(summary.totalCorpusFalseNegativeRate * 100).toFixed(1)}% (${summary.falseNegativesCount}/${summary.totalMaliciousCases})]`);
  console.log(`   - Indeterminate Rate:                     ${(summary.indeterminateRate * 100).toFixed(1)}% (${summary.indeterminateCount}/${summary.totalCases}) [Benign: ${summary.indeterminateBenignCases}/${summary.totalBenignCases}, Malicious: ${summary.indeterminateMaliciousCases}/${summary.totalMaliciousCases}]`);
  console.log(`   - Evidence Integrity Violations:          ${summary.evidenceIntegrityViolationsCount}`);
  console.log(`   - Scam-Type Determinate Accuracy:         ${(summary.scamTypeDeterminateAccuracy * 100).toFixed(1)}%`);
  console.log('======================================================================\n');
}

function generateMarkdownReport(summary: RedTeamBenchmarkSummary): string {
  const meta = summary.metadata;

  return `# HARIS (حارس) — Adversarial Red-Team Evaluation Report
**Report Version:** 1.0.0  
**Phase:** Phase 6B (Red-Team & Adversarial Evaluation)  
**Evaluation Date:** ${summary.evaluatedAt}  
**Pipeline Mode:** ${meta.pipelineMode}  

---

## 1. Executive Summary

This report documents the formal **Phase 6B Red-Team and Adversarial Evaluation** of the **HARIS Arabic Scam Intelligence Engine** across all **16 threat taxonomy categories** specified in \`evaluation/RED_TEAM_TAXONOMY.md\`.

The goal of this evaluation is to systematically stress-test and probe vulnerabilities in the approved baseline system before implementing tuning, weights adjustments, or prompt changes.

### Key Headline Metrics
- **Total Attack Corpus:** ${summary.totalCases} cases across 16 categories.
- **Case-Level Failure Count:** **${summary.failedCasesCount} / ${summary.totalCases}** (**${(summary.overallFailureRate * 100).toFixed(1)}%** of cases triggered at least one failure mode).
- **Cumulative Defect Instances:** **${summary.totalFailuresCount}** failure mode instances logged across failing cases.
- **Determinate False Positive Rate (FPR):** **${(summary.determinateFalsePositiveRate * 100).toFixed(1)}%** (${summary.falsePositivesCount}/${summary.determinateBenignCases} determinate benign cases misclassified) | Total-Corpus FPR: ${(summary.totalCorpusFalsePositiveRate * 100).toFixed(1)}% (${summary.falsePositivesCount}/${summary.totalBenignCases}).
- **Determinate False Negative Rate (FNR):** **${(summary.determinateFalseNegativeRate * 100).toFixed(1)}%** (${summary.falseNegativesCount}/${summary.determinateMaliciousCases} determinate evasion cases misclassified) | Total-Corpus FNR: ${(summary.totalCorpusFalseNegativeRate * 100).toFixed(1)}% (${summary.falseNegativesCount}/${summary.totalMaliciousCases}).
- **Indeterminate Rate (Screenshots):** **${(summary.indeterminateRate * 100).toFixed(1)}%** (${summary.indeterminateCount}/${summary.totalCases} total) — Breakdown: Benign Indeterminate = ${(summary.benignIndeterminateRate * 100).toFixed(1)}% (${summary.indeterminateBenignCases}/${summary.totalBenignCases}), Malicious Indeterminate = ${(summary.maliciousIndeterminateRate * 100).toFixed(1)}% (${summary.indeterminateMaliciousCases}/${summary.totalMaliciousCases}).
- **Evidence Integrity Violations:** **${summary.evidenceIntegrityViolationsCount}** recorded across all cases.
- **Scam-Type Attribution Accuracy (Determinate Scams):** **${(summary.scamTypeDeterminateAccuracy * 100).toFixed(1)}%**.

---

## 2. Attack Coverage & Reproducibility Metadata

| Metadata Field | Value | Notes |
|---|---|---|
| **Evaluation Source Commit** | \`${meta.evaluationSourceCommit}\` | Exact Git commit of codebase during evaluation |
| **Dataset Version** | \`${meta.datasetVersion}\` | 48-case dedicated Red-Team corpus |
| **Dataset SHA-256** | \`${meta.datasetSha256.substring(0, 32)}...\` | Tamper-evident cryptographic hash |
| **Runner Version** | \`${meta.runnerVersion}\` | Phase 6B Red-Team evaluator |
| **Node.js Environment** | \`${meta.nodeVersion}\` | Runtime environment |
| **Gemini AI Configuration** | \`${meta.geminiConfigured ? 'Enabled' : 'Disabled / Offline Baseline'}\` | Deterministic baseline mode |
| **Categories Evaluated** | \`16 / 16 (100%)\` | Full coverage of RED_TEAM_TAXONOMY.md |

---

## 3. Results by Taxonomy Category

| Category # | Adversarial Taxonomy Category | Total | Failed | Failure Rate | FP | FN | Evidence Violations | Avg Score |
|---|---|---|---|---|---|---|---|---|
${Object.values(summary.categoryBreakdown)
  .map(
    (c) =>
      `| **${c.categoryName.split('.')[0]}** | ${c.categoryName.split('. ')[1]} | ${c.totalCases} | ${c.failedCases} | **${(c.failureRate * 100).toFixed(1)}%** | ${c.falsePositives} | ${c.falseNegatives} | ${c.evidenceViolations} | ${c.averageScore} |`
  )
  .join('\n')}

---

## 4. Results by Dialect

| Dialect | Description | Total Cases | Failed Cases | Failure Rate |
|---|---|---|---|---|
${Object.values(summary.dialectBreakdown)
  .map(
    (d) =>
      `| **${d.dialect.toUpperCase()}** | ${getDialectDescription(d.dialect)} | ${d.totalCases} | ${d.failedCases} | **${(d.failureRate * 100).toFixed(1)}%** |`
  )
  .join('\n')}

---

## 5. Results by Modality

| Modality | Description | Total Cases | Failed Cases | Failure Rate |
|---|---|---|---|---|
${Object.values(summary.modalityBreakdown)
  .map(
    (m) =>
      `| **${m.modality.toUpperCase()}** | ${getModalityDescription(m.modality)} | ${m.totalCases} | ${m.failedCases} | **${(m.failureRate * 100).toFixed(1)}%** |`
  )
  .join('\n')}

---

## 6. False Positives Breakdown (Benign Stress Tests)

${
  summary.caseResults.filter((c) => c.isFalsePositive).length === 0
    ? '> ✅ **Zero False Positives:** None of the benign adversarial inputs were misclassified as high or suspicious risk.'
    : summary.caseResults
        .filter((c) => c.isFalsePositive)
        .map(
          (c) => `### [${c.id}] ${c.title}
- **Category:** ${c.taxonomyCategoryName} (${c.dialect.toUpperCase()})
- **Actual Assigned Risk:** \`${c.actualRiskCategory.toUpperCase()}\` (Score: ${c.riskScore}) | Expected: \`LOW\`
- **Triggered Features:** \`[${c.actualDnaFeatures.join(', ')}]\`
- **Failures:**
${c.failures.map((f) => `  - **[${f.severity}]** ${f.description}`).join('\n')}
`
        )
        .join('\n')
}

---

## 7. False Negatives Breakdown (Malicious Evasion Attacks)

${
  summary.caseResults.filter((c) => c.isFalseNegative).length === 0
    ? '> ✅ **Zero False Negatives:** All malicious evasion attacks were successfully intercepted.'
    : summary.caseResults
        .filter((c) => c.isFalseNegative)
        .map(
          (c) => `### [${c.id}] ${c.title}
- **Category:** ${c.taxonomyCategoryName} (${c.dialect.toUpperCase()})
- **Actual Assigned Risk:** \`${c.actualRiskCategory.toUpperCase()}\` (Score: ${c.riskScore}) | Expected: \`${c.expectedRiskCategory.toUpperCase()}\`
- **Expected Scam Type:** \`${c.expectedScamType}\` | Actual: \`${c.actualScamType}\`
- **Expected Features:** \`[${c.expectedDnaFeatures.join(', ')}]\` | Detected: \`[${c.actualDnaFeatures.join(', ')}]\`
- **Vulnerability Reason:** ${c.failures.find((f) => f.category === 'FALSE_NEGATIVE')?.description || 'Low risk score evasion'}
`
        )
        .join('\n')
}

---

## 8. Scam DNA Failures & Feature Recall

| Feature Key | Feature Name (Arabic) | Expected Count | Detected Count | Recall |
|---|---|---|---|---|
${summary.dnaFeatureRecall
  .map(
    (f) =>
      `| \`${f.feature}\` | ${getFeatureArabicName(f.feature)} | ${f.expectedCount} | ${f.detectedCount} | ${f.recall === null ? 'N/A (0/0)' : `**${(f.recall * 100).toFixed(1)}%**`} |`
  )
  .join('\n')}

---

## 9. Scam-Type Failures & Misattributions

${
  summary.caseResults.filter((c) => c.failures.some((f) => f.category === 'WRONG_SCAM_TYPE')).length === 0
    ? '> ✅ No misattributions recorded on detected scams.'
    : summary.caseResults
        .filter((c) => c.failures.some((f) => f.category === 'WRONG_SCAM_TYPE'))
        .map(
          (c) => `- **[${c.id}] ${c.title}**: Expected \`${c.expectedScamType}\`, but engine assigned \`${c.actualScamType}\` (Score: ${c.riskScore}).`
        )
        .join('\n')
}

---

## 10. Evidence Integrity Failures

${
  summary.evidenceIntegrityViolationsCount === 0
    ? '> ✅ **Zero Evidence Integrity Violations:** No ungrounded evidence quotes, forbidden feature triggers, or unsubstantiated high-risk verdicts occurred.'
    : summary.caseResults
        .filter((c) => c.evidenceIntegrityViolations.length > 0)
        .map(
          (c) => `### [${c.id}] ${c.title}
- **Category:** ${c.taxonomyCategoryName}
${c.evidenceIntegrityViolations.map((v) => `- **[${v.severity}] Rule \`${v.rule}\`:** ${v.description}`).join('\n')}
`
        )
        .join('\n')
}

---

## 11. Highest-Severity Attack Cases (Critical & High)

${summary.highestSeverityFailures
  .slice(0, 10)
  .map(
    (c, idx) => `### ${idx + 1}. [${c.id}] ${c.title}
- **Category:** ${c.taxonomyCategoryName} | **Dialect:** ${c.dialect.toUpperCase()} | **Modality:** ${c.modality.toUpperCase()}
- **Expected Risk:** \`${c.expectedRiskCategory.toUpperCase()}\` | **Actual Risk:** \`${c.actualRiskCategory.toUpperCase()}\` (Score: ${c.riskScore})
- **Failures:**
${c.failures.map((f) => `  - **[${f.severity}] ${f.category}:** ${f.description}`).join('\n')}
`
  )
  .join('\n')}

---

## 12. Recommended Fix Areas (For Phase 6C/7 — WITHOUT IMPLEMENTATION)

> [!IMPORTANT]
> In accordance with Phase 6B constraints, **NO fixes or weights modifications have been made**. These recommendations are logged for future hardening phases:

1. **Arabizi Transliteration Normalizer (Category 5):**
   - The deterministic engine relies exclusively on Arabic characters. Adding an Arabizi phonetic dictionary or transliteration preprocessor is required to capture scams written in Latin numerals (e.g. \`7sabk\`, \`t36l\`, \`3shan\`).

2. **Unicode Normalization & Tatweel Stripping (Category 6):**
   - Implementing NFKC canonical normalization and stripping zero-width spaces (\`\\u200B\`) and tatweel (\`ـ\`) prior to regex scanning will close simple evasion loops.

3. **Multi-URL Exhaustive Inspection (Category 12):**
   - When multiple URLs are detected, ensure the worst-case malicious indicator strictly dominates rather than averaging signals or only evaluating the primary link.

4. **Phone Directing & Social Engineering Patterns (Category 14):**
   - Enhance non-URL scam detection by recognizing unsolicited phone directives combined with cash lures (\`2 مليون ريال\`, \`صراف الكريمي\`, \`تواصل عبر الواتساب\`).

5. **Contextual Polarity Preservation (Category 1 & 2):**
   - Continue strictly enforcing clause-level negation (\`لن يطلب قط\`, \`إياك ومشاركة\`) to guarantee zero false positives on institutional security advisories.
`;
}

function getDialectDescription(d: string): string {
  switch (d) {
    case 'msa':
      return 'Modern Standard Arabic (فصحى)';
    case 'yemeni':
      return 'Yemeni Colloquial Arabic (لهجة يمنية)';
    case 'gulf':
      return 'Gulf Colloquial Arabic (لهجة خليجية)';
    case 'egyptian':
      return 'Egyptian Colloquial Arabic (لهجة مصرية)';
    case 'mixed_en':
      return 'Bilingual Arabic + English (ثنائي اللغة)';
    case 'arabizi':
      return 'Arabizi Latin Transliteration (عربيزي)';
    case 'broken_arabic':
      return 'Machine-Translated / Broken Arabic (لغة مترجمة ركيكة)';
    default:
      return d;
  }
}

function getModalityDescription(m: string): string {
  switch (m) {
    case 'text':
      return 'Text Message Only (رسالة نصية فقط)';
    case 'url':
      return 'URL Link Only (رابط إنترنت فقط)';
    case 'text_url':
      return 'Text + Embedded Link (نص + رابط)';
    case 'screenshot':
      return 'Screenshot Image (لقطة شاشة مصورة)';
    default:
      return m;
  }
}

function getFeatureArabicName(feature: string): string {
  const map: Record<string, string> = {
    urgency: 'استعجال وضغط زمني',
    credential_request: 'طلب بيانات اعتماد',
    otp_request: 'طلب رمز التحقق OTP',
    impersonation: 'انتحال صفة رسمية',
    financial_lure: 'إغراء مالي وجوائز',
    suspicious_url: 'رابط مشبوه وتصيد',
    threat_language: 'تهديد وإيقاف خدمات',
    unexpected_contact: 'اتصال غير متوقع',
    secrecy_pressure: 'ضغط كتمان وسرية',
    suspicious_payment_request: 'طلب دفع مالي مريب',
    action_pressure: 'ضغط لاتخاذ إجراء فوري',
  };
  return map[feature] || feature;
}

runRedTeamEvaluation().catch((err) => {
  console.error('Fatal Red-Team Runner Error:', err);
  process.exit(1);
});
