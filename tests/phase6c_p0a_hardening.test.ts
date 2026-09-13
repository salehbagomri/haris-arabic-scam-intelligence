/**
 * HARIS (حارس) — Phase 6C Step 1: Arabizi + Unicode Robustness (P0-A) Test Suite
 *
 * Focused tests for:
 * 1. RED-013 (Arabizi Bank OTP theft)
 * 2. RED-014 (Arabizi Fake Prize)
 * 3. RED-015 (Arabizi Delivery Scam)
 * 4. RED-018 (Unicode Confusables / Cyrillic Homoglyphs)
 * 5. Normal English remains normal (zero false positives)
 * 6. Ordinary Arabic remains unchanged semantically (zero false positives)
 * 7. Evidence provenance grounding across normalized representations
 * 8. Zero regression on existing hard negatives
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { RED_TEAM_DATASET } from '../evaluation/red_team/dataset';
import { evaluateRedTeamItem, normalizeForContainment } from '../evaluation/red_team/evaluator';
import { EVALUATION_DATASET } from '../evaluation/dataset';
import { analyzeUnified } from '../lib/vision';
import { normalizeArabicText } from '../lib/analysis/normalizer';

describe('Phase 6C Step 1: Normalizer Metadata Flags', () => {
  it('correctly sets hasArabizi and hasObfuscation flags without destroying text', () => {
    const arabiziInput = 'ya 5oy 7sabk t36l 3shan el t7deeth. d5ol hna w 7ot el OTP bsor3a';
    const arabiziRes = normalizeArabicText(arabiziInput);
    assert.strictEqual(arabiziRes.hasArabizi, true);
    assert.strictEqual(arabiziRes.originalText, arabiziInput);

    const homoglyphInput = 'إشعаر مالي: تم إيقаف محفظتك';
    const homoglyphRes = normalizeArabicText(homoglyphInput);
    assert.strictEqual(homoglyphRes.hasObfuscation, true);
    assert.strictEqual(homoglyphRes.originalText, homoglyphInput);
  });
});

describe('Phase 6C Step 1: P0-A Failure Cluster Unit Tests', () => {
  it('RED-013: successfully detects Arabizi bank OTP theft as HIGH risk BANK_IMPERSONATION', async () => {
    const item = RED_TEAM_DATASET.find((c) => c.id === 'RED-013')!;
    assert.ok(item, 'RED-013 must exist in red team dataset');

    const result = await evaluateRedTeamItem(item);

    assert.strictEqual(result.actualRiskCategory, 'high', `Expected HIGH risk, got ${result.actualRiskCategory}`);
    assert.ok(result.riskScore >= 60, `Expected score >= 60, got ${result.riskScore}`);
    assert.strictEqual(result.actualScamType, 'BANK_IMPERSONATION');
    assert.strictEqual(result.isScamTypeCorrect, true);

    // Verify expected DNA features
    for (const feat of item.expectedDnaFeatures) {
      assert.ok(
        result.actualDnaFeatures.includes(feat),
        `RED-013 missed expected feature: ${feat}. Actual: ${JSON.stringify(result.actualDnaFeatures)}`
      );
    }

    // Zero false negative, zero evidence integrity violations
    assert.strictEqual(result.isFalseNegative, false);
    assert.strictEqual(result.evidenceIntegrityViolations.length, 0);
  });

  it('RED-014: successfully detects Arabizi fake prize as HIGH risk FAKE_PRIZE', async () => {
    const item = RED_TEAM_DATASET.find((c) => c.id === 'RED-014')!;
    assert.ok(item, 'RED-014 must exist in red team dataset');

    const result = await evaluateRedTeamItem(item);

    assert.strictEqual(result.actualRiskCategory, 'high', `Expected HIGH risk, got ${result.actualRiskCategory}`);
    assert.ok(result.riskScore >= 60, `Expected score >= 60, got ${result.riskScore}`);
    assert.strictEqual(result.actualScamType, 'FAKE_PRIZE');
    assert.strictEqual(result.isScamTypeCorrect, true);

    for (const feat of item.expectedDnaFeatures) {
      assert.ok(
        result.actualDnaFeatures.includes(feat),
        `RED-014 missed expected feature: ${feat}. Actual: ${JSON.stringify(result.actualDnaFeatures)}`
      );
    }

    assert.strictEqual(result.isFalseNegative, false);
    assert.strictEqual(result.evidenceIntegrityViolations.length, 0);
  });

  it('RED-015: successfully detects Arabizi delivery scam as HIGH risk DELIVERY_SCAM', async () => {
    const item = RED_TEAM_DATASET.find((c) => c.id === 'RED-015')!;
    assert.ok(item, 'RED-015 must exist in red team dataset');

    const result = await evaluateRedTeamItem(item);

    assert.strictEqual(result.actualRiskCategory, 'high', `Expected HIGH risk, got ${result.actualRiskCategory}`);
    assert.ok(result.riskScore >= 60, `Expected score >= 60, got ${result.riskScore}`);
    assert.strictEqual(result.actualScamType, 'DELIVERY_SCAM');
    assert.strictEqual(result.isScamTypeCorrect, true);

    for (const feat of item.expectedDnaFeatures) {
      assert.ok(
        result.actualDnaFeatures.includes(feat),
        `RED-015 missed expected feature: ${feat}. Actual: ${JSON.stringify(result.actualDnaFeatures)}`
      );
    }

    assert.strictEqual(result.isFalseNegative, false);
    assert.strictEqual(result.evidenceIntegrityViolations.length, 0);
  });

  it('RED-018: successfully detects Cyrillic homoglyph obfuscation as HIGH risk ACCOUNT_TAKEOVER', async () => {
    const item = RED_TEAM_DATASET.find((c) => c.id === 'RED-018')!;
    assert.ok(item, 'RED-018 must exist in red team dataset');

    const result = await evaluateRedTeamItem(item);

    assert.strictEqual(result.actualRiskCategory, 'high', `Expected HIGH risk, got ${result.actualRiskCategory}`);
    assert.ok(result.riskScore >= 60, `Expected score >= 60, got ${result.riskScore}`);
    assert.strictEqual(result.actualScamType, 'ACCOUNT_TAKEOVER');
    assert.strictEqual(result.isScamTypeCorrect, true);

    for (const feat of item.expectedDnaFeatures) {
      assert.ok(
        result.actualDnaFeatures.includes(feat),
        `RED-018 missed expected feature: ${feat}. Actual: ${JSON.stringify(result.actualDnaFeatures)}`
      );
    }

    assert.strictEqual(result.isFalseNegative, false);
    assert.strictEqual(result.evidenceIntegrityViolations.length, 0);
  });
});

describe('Phase 6C Step 1: False Positive & Grounding Safeguards', () => {
  it('normal English messages remain classified as LOW risk with 0 scam features', async () => {
    const englishSamples = [
      'Team meeting tomorrow at 10am to discuss sprint goals and backlog.',
      'Please review PR #124 for the authentication gateway v2.',
      'Quarterly financial summary: net revenue grew by 15% in Q3.',
      'Looking forward to catching up over lunch next Tuesday.',
    ];

    for (const text of englishSamples) {
      const res = await analyzeUnified({ text });
      assert.strictEqual(res.riskLevel, 'low', `English sample falsely flagged: "${text}" -> ${res.riskLevel} (${res.riskScore})`);
      assert.ok(res.riskScore <= 25, `Expected score <= 25, got ${res.riskScore} for: "${text}"`);
      assert.strictEqual(res.detectedFeatures.length, 0, `Expected 0 features, got: ${JSON.stringify(res.detectedFeatures)}`);
    }
  });

  it('ordinary Arabic messages remain unchanged semantically with LOW risk', async () => {
    const ordinaryArabicSamples = [
      'السلام عليكم ورحمة الله، نأمل التكرم بإرسال التقرير الشهري لمراجعته مع المدير.',
      'أهلاً وسهلاً بك، تم تأكيد حجز موعدك في العيادة يوم الأحد القادم في تمام الساعة الرابعة.',
      'مرحباً يا أخي، هل يمكنك إرسال موقع المنزل عبر خرائط جوجل لنلتقي هناك الليلة؟',
    ];

    for (const text of ordinaryArabicSamples) {
      const res = await analyzeUnified({ text });
      assert.strictEqual(res.riskLevel, 'low', `Ordinary Arabic falsely flagged: "${text}" -> ${res.riskLevel}`);
      assert.ok(res.riskScore <= 25);
      assert.strictEqual(res.detectedFeatures.length, 0);
    }
  });

  it('all extracted evidence quotes across target RED cases are strictly grounded in source input', async () => {
    const targetIds = ['RED-013', 'RED-014', 'RED-015', 'RED-018'];

    for (const id of targetIds) {
      const item = RED_TEAM_DATASET.find((c) => c.id === id)!;
      const res = await analyzeUnified(item.input);

      const sourceText = item.input.text || '';
      const sourceUrl = item.input.url || '';
      const combinedSource = `${sourceText} ${sourceUrl}`;
      const normalizedSource = normalizeForContainment(combinedSource);

      for (const indicator of res.scamDna || []) {
        for (const quote of indicator.evidence || []) {
          if (quote && quote.trim().length > 3) {
            const normalizedQuote = normalizeForContainment(quote);
            assert.ok(
              normalizedSource.includes(normalizedQuote),
              `Case ${id}: Evidence quote "${quote}" (normalized: "${normalizedQuote}") is not grounded in input text: "${normalizedSource}"`
            );
          }
        }
      }
    }
  });

  it('zero regressions on baseline hard negative cases (LEGIT-001, LEGIT-002, LEGIT-012, LEGIT-013)', async () => {
    const legitIds = ['LEGIT-001', 'LEGIT-002', 'LEGIT-012', 'LEGIT-013'];

    for (const id of legitIds) {
      const item = EVALUATION_DATASET.find((c) => c.id === id);
      assert.ok(item, `Case ${id} must exist in evaluation dataset`);

      const res = await analyzeUnified(item.input);
      assert.strictEqual(
        res.riskLevel,
        'low',
        `Regression on ${id} (${item.title}): expected low risk, got ${res.riskLevel} (score: ${res.riskScore})`
      );
      assert.strictEqual(
        res.scamType,
        'UNKNOWN',
        `Regression on ${id}: expected UNKNOWN scam type, got ${res.scamType}`
      );
    }
  });

  it('zero regressions on red-team hard negative categories (RED-001, RED-007, RED-010)', async () => {
    const redNegatives = ['RED-001', 'RED-007', 'RED-010'];

    for (const id of redNegatives) {
      const item = RED_TEAM_DATASET.find((c) => c.id === id);
      assert.ok(item, `Case ${id} must exist in red team dataset`);

      const evalRes = await evaluateRedTeamItem(item);
      assert.strictEqual(
        evalRes.actualRiskCategory,
        'low',
        `Regression on ${id}: expected low risk, got ${evalRes.actualRiskCategory} (score: ${evalRes.riskScore})`
      );
      assert.strictEqual(evalRes.isFalsePositive, false);
      assert.strictEqual(evalRes.evidenceIntegrityViolations.length, 0);
    }
  });
});
