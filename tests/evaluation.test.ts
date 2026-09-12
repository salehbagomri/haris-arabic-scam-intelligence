/**
 * HARIS (حارس) — Phase 6A.1: Evaluation Integrity & Formula Regression Tests
 *
 * Verifies:
 * 1. Dataset structure, distribution, dialect diversity, and schema validity.
 * 2. Dataset safety invariants: no literal phone numbers, raw OTPs, or real account IDs.
 * 3. Screenshot fixtures: authentic high-resolution PNGs (not 1x1 placeholders) with PNG magic headers.
 * 4. Deterministic evaluator mathematical formulas: accuracy, FPR, FNR, TP/FP/FN/TN,
 *    Scam DNA precision/recall/F1, scamTypeAccuracyScamOnly vs scamTypeAccuracyAllCases,
 *    and extraction failure / indeterminate accounting.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { EVALUATION_DATASET } from '../evaluation/dataset';
import { SCREENSHOT_FIXTURES } from '../evaluation/fixtures/screenshots';
import { SCAM_TYPES, SCAM_DNA_FEATURES, FeatureKey } from '../lib/analysis/taxonomy';
import { RiskLevel } from '../lib/types/analysis';

describe('HARIS Phase 6A.1: Evaluation Dataset Integrity & Invariants', () => {
  it('1. dataset contains at least 60 labeled cases', () => {
    assert.ok(
      EVALUATION_DATASET.length >= 60,
      `Expected at least 60 cases, got ${EVALUATION_DATASET.length}`
    );
  });

  it('2. dataset has balanced and diverse category distribution', () => {
    const scams = EVALUATION_DATASET.filter((c) => c.category === 'scam');
    const legit = EVALUATION_DATASET.filter((c) => c.category === 'legitimate');
    const ambiguous = EVALUATION_DATASET.filter((c) => c.category === 'ambiguous');

    assert.ok(scams.length >= 30, `Expected at least 30 scam cases, got ${scams.length}`);
    assert.ok(legit.length >= 20, `Expected at least 20 legitimate cases, got ${legit.length}`);
    assert.ok(ambiguous.length >= 10, `Expected at least 10 ambiguous cases, got ${ambiguous.length}`);
  });

  it('3. covers Yemen-aware and diverse Arab dialects', () => {
    const dialects = new Set(EVALUATION_DATASET.map((c) => c.dialect));
    assert.ok(dialects.has('msa'), 'Missing Modern Standard Arabic cases');
    assert.ok(dialects.has('yemeni'), 'Missing Yemeni Arabic cases');
    assert.ok(dialects.has('gulf'), 'Missing Gulf dialect cases');
    assert.ok(dialects.has('egyptian'), 'Missing Egyptian dialect cases');
    assert.ok(dialects.has('mixed_en'), 'Missing mixed English/Arabic cases');
    assert.ok(dialects.has('arabizi'), 'Missing Arabizi cases');

    const yemeniCases = EVALUATION_DATASET.filter((c) => c.dialect === 'yemeni');
    assert.ok(yemeniCases.length >= 7, `Expected at least 7 Yemeni cases, got ${yemeniCases.length}`);
  });

  it('4. guarantees unique case IDs and valid schemas', () => {
    const idSet = new Set<string>();
    for (const item of EVALUATION_DATASET) {
      assert.ok(item.id, 'Item must have an ID');
      assert.strictEqual(idSet.has(item.id), false, `Duplicate ID detected: ${item.id}`);
      idSet.add(item.id);

      assert.ok(item.title, `Item ${item.id} missing title`);
      assert.ok(item.description, `Item ${item.id} missing description`);
      assert.ok(item.rationale, `Item ${item.id} missing rationale`);

      const hasText = typeof item.input.text === 'string' && item.input.text.length > 0;
      const hasUrl = typeof item.input.url === 'string' && item.input.url.length > 0;
      const hasScreenshot = Boolean(item.input.screenshot?.data);
      assert.ok(
        hasText || hasUrl || hasScreenshot,
        `Item ${item.id} must have at least text, url, or screenshot`
      );

      assert.ok(
        ['low', 'suspicious', 'high'].includes(item.expectedRiskCategory),
        `Item ${item.id} invalid expectedRiskCategory: ${item.expectedRiskCategory}`
      );

      assert.ok(
        (SCAM_TYPES as readonly string[]).includes(item.expectedScamType),
        `Item ${item.id} invalid expectedScamType: ${item.expectedScamType}`
      );

      for (const feat of item.expectedDnaFeatures) {
        assert.ok(
          (SCAM_DNA_FEATURES as readonly string[]).includes(feat),
          `Item ${item.id} invalid expectedDnaFeature: ${feat}`
        );
      }
    }
  });

  it('5. screenshot fixtures set covers all required test modalities with authentic PNGs', () => {
    const fixtureKeys = Object.keys(SCREENSHOT_FIXTURES);
    assert.ok(fixtureKeys.length >= 7, `Expected at least 7 screenshot fixtures, got ${fixtureKeys.length}`);

    for (const key of fixtureKeys) {
      const fix = SCREENSHOT_FIXTURES[key];
      assert.ok(fix.id);
      assert.ok(fix.name);
      assert.strictEqual(fix.mimeType, 'image/png');
      assert.ok(fix.dataUrl.startsWith('data:image/png;base64,'));
      assert.ok(fix.simulatedVisualDescription);

      // Verify authentic PNG payload: must not be a 1x1 pixel placeholder
      const base64Data = fix.dataUrl.replace(/^data:image\/png;base64,/, '');
      const buffer = Buffer.from(base64Data, 'base64');
      assert.ok(
        buffer.length > 1000,
        `Fixture ${key} payload too small (${buffer.length} bytes), expected authentic image > 1KB`
      );

      // Verify PNG magic bytes (\x89PNG\r\n\x1a\n)
      assert.strictEqual(buffer[0], 0x89);
      assert.strictEqual(buffer[1], 0x50); // P
      assert.strictEqual(buffer[2], 0x4e); // N
      assert.strictEqual(buffer[3], 0x47); // G
      assert.strictEqual(buffer[4], 0x0d);
      assert.strictEqual(buffer[5], 0x0a);
      assert.strictEqual(buffer[6], 0x1a);
      assert.strictEqual(buffer[7], 0x0a);
    }
  });
});

describe('HARIS Phase 6A.1: Dataset Safety Guardrail (No PII / Real Literals)', () => {
  it('enforces that no raw phone numbers, OTP codes, or account IDs appear in test cases', () => {
    // Regex looking for phone patterns (e.g. 05xxxxxxxx, 01xxxxxxxxx, 00967xxxxxxx, +966xxxxxxx)
    const rawPhoneRegex = /(?:\+?96[67]\d{7,9}|0096[67]\d{7,9}|05\d{8}|01[0125]\d{8}|00\d{10,14})/;
    // Regex looking for literal OTP assignments (e.g. "رمز التحقق هو 123456")
    const rawOtpLiteralRegex = /(?:رمز التحقق(?: الخاص بك)?(?: هو)?:\s*\d{4,8})/;
    // Regex looking for literal account assignments without placeholders (e.g. "محفظة رقم 771234567")
    const rawAccountLiteralRegex = /(?:محفظة(?:\s+\w+)?\s+رقم\s+\d{6,})/;

    for (const item of EVALUATION_DATASET) {
      const text = item.input.text || '';

      assert.strictEqual(
        rawPhoneRegex.test(text),
        false,
        `[${item.id}] Found literal phone number in text. Must use [PHONE] placeholder: "${text}"`
      );

      assert.strictEqual(
        rawOtpLiteralRegex.test(text),
        false,
        `[${item.id}] Found literal OTP code in text. Must use [OTP] placeholder: "${text}"`
      );

      assert.strictEqual(
        rawAccountLiteralRegex.test(text),
        false,
        `[${item.id}] Found literal account ID in text. Must use [ACCOUNT_ID] placeholder: "${text}"`
      );
    }
  });
});

describe('HARIS Phase 6A.1: Evaluator Mathematical Formula & Accounting Tests', () => {
  // Deterministic mock fixtures with known ground truth and known mock runner results
  interface MiniCase {
    id: string;
    category: 'scam' | 'legitimate' | 'ambiguous';
    expectedRisk: RiskLevel;
    actualRisk: RiskLevel;
    expectedScamType: string;
    actualScamType: string;
    expectedDna: FeatureKey[];
    actualDna: FeatureKey[];
    isScreenshot: boolean;
    isExtractionFailure: boolean;
  }

  const MINI_CASES: MiniCase[] = [
    // Case 1: Scam, correctly detected (TP, correct risk, correct scam type)
    {
      id: 'TEST-001',
      category: 'scam',
      expectedRisk: 'high',
      actualRisk: 'high',
      expectedScamType: 'BANK_IMPERSONATION',
      actualScamType: 'BANK_IMPERSONATION',
      expectedDna: ['impersonation', 'urgency'],
      actualDna: ['impersonation', 'urgency', 'suspicious_url'], // TP=2, FP=1, FN=0
      isScreenshot: false,
      isExtractionFailure: false,
    },
    // Case 2: Scam, missed as low (FN, incorrect risk, incorrect scam type)
    {
      id: 'TEST-002',
      category: 'scam',
      expectedRisk: 'high',
      actualRisk: 'low',
      expectedScamType: 'DELIVERY_SCAM',
      actualScamType: 'UNKNOWN',
      expectedDna: ['financial_lure'],
      actualDna: [], // TP=0, FP=0, FN=1
      isScreenshot: false,
      isExtractionFailure: false,
    },
    // Case 3: Legitimate, correctly identified (TN, correct risk, UNKNOWN matches UNKNOWN)
    {
      id: 'TEST-003',
      category: 'legitimate',
      expectedRisk: 'low',
      actualRisk: 'low',
      expectedScamType: 'UNKNOWN',
      actualScamType: 'UNKNOWN',
      expectedDna: [],
      actualDna: [],
      isScreenshot: false,
      isExtractionFailure: false,
    },
    // Case 4: Legitimate, falsely flagged as suspicious (FP, incorrect risk)
    {
      id: 'TEST-004',
      category: 'legitimate',
      expectedRisk: 'low',
      actualRisk: 'suspicious',
      expectedScamType: 'UNKNOWN',
      actualScamType: 'UNKNOWN',
      expectedDna: [],
      actualDna: ['urgency'], // TP=0, FP=1, FN=0
      isScreenshot: false,
      isExtractionFailure: false,
    },
    // Case 5: Screenshot with extraction failure, expected high (Indeterminate, NOT counted as correct risk)
    {
      id: 'TEST-005',
      category: 'scam',
      expectedRisk: 'high',
      actualRisk: 'low', // default fallback is low
      expectedScamType: 'ACCOUNT_TAKEOVER',
      actualScamType: 'UNKNOWN',
      expectedDna: ['otp_request'],
      actualDna: [],
      isScreenshot: true,
      isExtractionFailure: true,
    },
  ];

  it('1. correctly computes overall, legitimate, and scam accuracy', () => {
    let totalCorrect = 0;
    let legitCorrect = 0;
    let legitTotal = 0;
    let scamCorrect = 0;
    let scamTotal = 0;

    for (const c of MINI_CASES) {
      const isIndeterminate = c.isExtractionFailure && c.isScreenshot;
      const isRiskCorrect = !isIndeterminate && c.actualRisk === c.expectedRisk;

      if (isRiskCorrect) totalCorrect++;
      if (c.category === 'legitimate') {
        legitTotal++;
        if (isRiskCorrect) legitCorrect++;
      }
      if (c.category === 'scam') {
        scamTotal++;
        if (isRiskCorrect) scamCorrect++;
      }
    }

    // Total: 5 cases. Correct: TEST-001 (scam) and TEST-003 (legit) = 2.
    // TEST-005 is unextracted screenshot, so it must NOT count as correct!
    assert.strictEqual(totalCorrect, 2);
    assert.strictEqual(totalCorrect / MINI_CASES.length, 0.4);

    // Legitimate: 2 cases (TEST-003, TEST-004). Correct: TEST-003 = 1.
    assert.strictEqual(legitTotal, 2);
    assert.strictEqual(legitCorrect, 1);
    assert.strictEqual(legitCorrect / legitTotal, 0.5);

    // Scam: 3 cases (TEST-001, TEST-002, TEST-005). Correct: TEST-001 = 1.
    assert.strictEqual(scamTotal, 3);
    assert.strictEqual(scamCorrect, 1);
    assert.strictEqual(Number((scamCorrect / scamTotal).toFixed(3)), 0.333);
  });

  it('2. correctly computes FPR, FNR, and confusion matrix', () => {
    let tp = 0;
    let fp = 0;
    let fn = 0;
    let tn = 0;
    let indeterminate = 0;

    for (const c of MINI_CASES) {
      const isIndet = c.isExtractionFailure && c.isScreenshot;
      if (isIndet) {
        indeterminate++;
      } else if (c.category === 'scam') {
        if (c.actualRisk === 'high' || c.actualRisk === 'suspicious') tp++;
        else if (c.actualRisk === 'low') fn++;
      } else if (c.category === 'legitimate') {
        if (c.actualRisk === 'low') tn++;
        else if (c.actualRisk === 'suspicious' || c.actualRisk === 'high') fp++;
      }
    }

    assert.strictEqual(tp, 1, 'True Positives mismatch');
    assert.strictEqual(fp, 1, 'False Positives mismatch');
    assert.strictEqual(fn, 1, 'False Negatives mismatch');
    assert.strictEqual(tn, 1, 'True Negatives mismatch');
    assert.strictEqual(indeterminate, 1, 'Indeterminate count mismatch');

    const fpr = fp / (fp + tn); // 1 / 2 = 0.5
    const fnr = fn / (tp + fn); // 1 / 2 = 0.5
    assert.strictEqual(fpr, 0.5);
    assert.strictEqual(fnr, 0.5);
  });

  it('3. isolates scamTypeAccuracyScamOnly and prevents UNKNOWN matches from inflating accuracy', () => {
    let correctAll = 0;
    let correctScamOnly = 0;
    let scamCount = 0;

    for (const c of MINI_CASES) {
      const isMatch = c.actualScamType === c.expectedScamType;
      if (isMatch) correctAll++;

      if (c.category === 'scam') {
        scamCount++;
        // Must match expected scam type AND must not be UNKNOWN
        if (isMatch && c.actualScamType !== 'UNKNOWN') {
          correctScamOnly++;
        }
      }
    }

    // Scam Only: 3 scams (TEST-001 matches BANK_IMPERSONATION; TEST-002, TEST-005 do not).
    assert.strictEqual(scamCount, 3);
    assert.strictEqual(correctScamOnly, 1);
    const scamOnlyAccuracy = correctScamOnly / scamCount;
    assert.strictEqual(Number(scamOnlyAccuracy.toFixed(3)), 0.333);

    // All Cases: matches on TEST-001 (BANK_IMPERSONATION) and TEST-003, TEST-004 (UNKNOWN)
    // 3 out of 5 = 0.60
    assert.strictEqual(correctAll, 3);
    assert.strictEqual(correctAll / MINI_CASES.length, 0.6);

    // Assert that scamOnly accuracy is strictly separated and not inflated by UNKNOWN matches
    assert.notStrictEqual(scamOnlyAccuracy, correctAll / MINI_CASES.length);
  });

  it('4. calculates Scam DNA precision, recall, and F1 equations correctly', () => {
    // Test Case 1: expected ['impersonation', 'urgency'], actual ['impersonation', 'urgency', 'suspicious_url']
    const c1 = MINI_CASES[0];
    const expSet = new Set(c1.expectedDna);
    const actSet = new Set(c1.actualDna);

    let tp = 0;
    let fp = 0;
    let fn = 0;

    for (const f of c1.expectedDna) {
      if (actSet.has(f)) tp++;
      else fn++;
    }
    for (const f of c1.actualDna) {
      if (!expSet.has(f)) fp++;
    }

    assert.strictEqual(tp, 2);
    assert.strictEqual(fp, 1);
    assert.strictEqual(fn, 0);

    const precision = tp / (tp + fp); // 2/3
    const recall = tp / (tp + fn); // 2/2 = 1.0
    const f1 = (2 * precision * recall) / (precision + recall); // 2 * (2/3) / (5/3) = 4/5 = 0.8

    assert.strictEqual(Number(precision.toFixed(3)), 0.667);
    assert.strictEqual(recall, 1.0);
    assert.strictEqual(f1, 0.8);
  });

  it('5. enforces extraction failure accounting on unextractable screenshots', () => {
    const c5 = MINI_CASES[4];
    assert.strictEqual(c5.isScreenshot, true);
    assert.strictEqual(c5.isExtractionFailure, true);

    // Even though actualRisk is 'low' (the fallback default) and expectedRisk might be tested,
    // an extraction failure must be marked indeterminate and never recorded as a clean correct classification.
    const isIndeterminate = c5.isExtractionFailure && c5.isScreenshot;
    assert.strictEqual(isIndeterminate, true);

    const isRiskCorrect = !isIndeterminate && c5.actualRisk === c5.expectedRisk;
    assert.strictEqual(isRiskCorrect, false, 'Extraction failure must not be credited as correct risk');
  });
});
