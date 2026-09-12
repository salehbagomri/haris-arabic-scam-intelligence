/**
 * HARIS (حارس) — Phase 6A.2: Evaluation Integrity & Formula Regression Tests
 *
 * Verifies:
 * 1. Dataset structure, distribution, dialect diversity, and schema validity.
 * 2. Comprehensive PII safety scan across all text, URLs, descriptions, rationales, and fixtures.
 * 3. Screenshot payload contract: real base64 PNGs matching production ScreenshotInput;
 *    zero data/description leakage; fallback reason is unconfigured Gemini, NOT missing payload.
 * 4. Pure metric calculation functions: zero-division safety, indeterminate isolation,
 *    FPR = FP/(TN+FP), determinate FNR, miss rate including indeterminate, and scam-type metrics.
 * 5. Runner integration and pipeline accounting with screenshot cases.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { EVALUATION_DATASET } from '../evaluation/dataset';
import { SCREENSHOT_FIXTURES } from '../evaluation/fixtures/screenshots';
import { SCAM_TYPES, SCAM_DNA_FEATURES } from '../lib/analysis/taxonomy';
import { validateImageConstraints } from '../lib/config/vision';
import { extractScreenshotContent } from '../lib/vision/analyzer';
import { analyzeUnified } from '../lib/vision/pipeline';
import {
  calculateConfusionMatrix,
  calculateRiskMetrics,
  calculateLegitimateMetrics,
  calculateScamMetrics,
  calculateScamTypeMetrics,
  calculatePrecision,
  calculateRecall,
  calculateF1,
} from '../evaluation/metrics';
import { EvaluationCaseResult } from '../evaluation/types';

describe('HARIS Phase 6A.2: Evaluation Dataset Integrity & Invariants', () => {
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
      const hasScreenshot = Boolean(item.input.screenshot?.base64);
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

      const base64Data = fix.dataUrl.replace(/^data:image\/png;base64,/, '');
      const buffer = Buffer.from(base64Data, 'base64');
      assert.ok(
        buffer.length > 1000,
        `Fixture ${key} payload too small (${buffer.length} bytes), expected authentic image > 1KB`
      );

      // Verify PNG magic header (\x89PNG\r\n\x1a\n)
      assert.strictEqual(buffer[0], 0x89);
      assert.strictEqual(buffer[1], 0x50);
      assert.strictEqual(buffer[2], 0x4e);
      assert.strictEqual(buffer[3], 0x47);
      assert.strictEqual(buffer[4], 0x0d);
      assert.strictEqual(buffer[5], 0x0a);
      assert.strictEqual(buffer[6], 0x1a);
      assert.strictEqual(buffer[7], 0x0a);
    }
  });
});

describe('HARIS Phase 6A.2: Comprehensive Dataset & Fixture Safety Guardrail (Zero PII)', () => {
  it('enforces that no raw phone numbers, OTP literals, or account IDs exist in any text field or fixture', () => {
    const rawPhoneRegex = /(?:\+?96[67]\d{7,9}|0096[67]\d{7,9}|05\d{8}|01[0125]\d{8}|00\d{10,14})/;
    const rawOtpLiteralRegex = /(?:رمز التحقق(?: الخاص بك)?(?: هو)?:\s*\d{4,8})/;
    const rawAccountLiteralRegex = /(?:محفظة(?:\s+\w+)?\s+رقم\s+\d{6,})/;

    // 1. Scan all fields across all dataset items
    for (const item of EVALUATION_DATASET) {
      const fieldsToScan: Record<string, string> = {
        title: item.title,
        description: item.description,
        rationale: item.rationale,
        text: item.input.text || '',
        url: item.input.url || '',
        adversarialSubtype: item.adversarialSubtype || '',
      };

      for (const [fieldName, val] of Object.entries(fieldsToScan)) {
        assert.strictEqual(
          rawPhoneRegex.test(val),
          false,
          `[${item.id}.${fieldName}] Found literal phone number: "${val}". Must use [PHONE] placeholder.`
        );

        assert.strictEqual(
          rawOtpLiteralRegex.test(val),
          false,
          `[${item.id}.${fieldName}] Found literal OTP code: "${val}". Must use [OTP] placeholder.`
        );

        assert.strictEqual(
          rawAccountLiteralRegex.test(val),
          false,
          `[${item.id}.${fieldName}] Found literal account ID: "${val}". Must use [ACCOUNT_ID] placeholder.`
        );
      }
    }

    // 2. Scan all fixture metadata text
    for (const [key, fix] of Object.entries(SCREENSHOT_FIXTURES)) {
      assert.strictEqual(
        rawPhoneRegex.test(fix.name) || rawPhoneRegex.test(fix.simulatedVisualDescription),
        false,
        `[Fixture ${key}] Found literal phone number in fixture text.`
      );
      assert.strictEqual(
        rawOtpLiteralRegex.test(fix.name) || rawOtpLiteralRegex.test(fix.simulatedVisualDescription),
        false,
        `[Fixture ${key}] Found literal OTP in fixture text.`
      );
    }
  });
});

describe('HARIS Phase 6A.2: Screenshot Payload Contract & Analyzer Verification', () => {
  it('1. verifies that all evaluation screenshot inputs match production ScreenshotInput and have zero data/description leakage', () => {
    const screenshotCases = EVALUATION_DATASET.filter((c) => Boolean(c.input.screenshot));
    assert.strictEqual(screenshotCases.length, 5, 'Expected exactly 5 screenshot cases in dataset');

    for (const c of screenshotCases) {
      const screenshot = c.input.screenshot!;
      assert.ok(screenshot.base64, `[${c.id}] screenshot.base64 must be defined`);
      assert.strictEqual(screenshot.mimeType, 'image/png');

      // Crucial: Old .data and .description must NOT exist on input
      const rawInput = screenshot as unknown as Record<string, unknown>;
      assert.strictEqual(rawInput.data, undefined, `[${c.id}] screenshot.data must not exist; use base64`);
      assert.strictEqual(
        rawInput.description,
        undefined,
        `[${c.id}] screenshot.description must not leak into production input`
      );
    }
  });

  it('2. confirms production validateImageConstraints accepts evaluation screenshot payloads', () => {
    const screenshotCases = EVALUATION_DATASET.filter((c) => Boolean(c.input.screenshot));

    for (const c of screenshotCases) {
      const validation = validateImageConstraints(c.input.screenshot!);
      assert.strictEqual(validation.valid, true, `[${c.id}] Screenshot payload failed constraint validation: ${validation.error}`);
      assert.ok(validation.byteLength && validation.byteLength > 1000, `[${c.id}] Byte length must be > 1KB`);
    }
  });

  it('3. confirms extractScreenshotContent fallback reason is unconfigured Gemini, NOT missing image payload', async () => {
    const sampleScreenshotCase = EVALUATION_DATASET.find((c) => c.id === 'SCAM-033');
    assert.ok(sampleScreenshotCase?.input.screenshot);

    const result = await extractScreenshotContent(sampleScreenshotCase.input.screenshot, {});
    assert.strictEqual(result.success, false);
    // Must fail because Gemini is unconfigured, NOT because image data was missing
    assert.ok(
      result.fallbackReason?.includes('Gemini') && result.fallbackReason?.includes('not configured'),
      `Expected unconfigured Gemini fallback, got: ${result.fallbackReason}`
    );
    assert.notStrictEqual(result.fallbackReason, 'No image data provided (neither buffer nor base64).');
    assert.notStrictEqual(result.fallbackReason, 'Missing image payload (no buffer or base64 string provided).');
  });

  it('4. confirms analyzeUnified marks screenshot-only inputs as isExtractionFailure: true and returns structured advice', async () => {
    const sampleScreenshotCase = EVALUATION_DATASET.find((c) => c.id === 'SCAM-033');
    assert.ok(sampleScreenshotCase);

    const result = await analyzeUnified(sampleScreenshotCase.input);
    assert.strictEqual(result.isExtractionFailure, true);
    assert.strictEqual(result.riskLevel, 'low'); // default fallback structure
    assert.strictEqual(result.riskScore, 0);
    assert.ok(result.uncertainties.some((u) => u.includes('فشل استخراج محتوى لقطة الشاشة')));
    assert.ok(result.actionableAdvice.some((a) => a.includes('يرجى إعادة رفع لقطة شاشة')));
  });
});

describe('HARIS Phase 6A.2: Pure Metric Calculation Functions & Granular Accounting', () => {
  // Controlled mock dataset to test all mathematical equations deterministically
  const MOCK_CASE_RESULTS: EvaluationCaseResult[] = [
    // 1. Scam: Detected (TP, correct risk, correct scam type)
    {
      id: 'MOCK-001',
      title: 'Scam TP',
      category: 'scam',
      dialect: 'msa',
      expectedRiskCategory: 'high',
      actualRiskCategory: 'high',
      riskScore: 85,
      expectedScamType: 'BANK_IMPERSONATION',
      actualScamType: 'BANK_IMPERSONATION',
      expectedDnaFeatures: ['impersonation'],
      actualDnaFeatures: ['impersonation'],
      isRiskCategoryCorrect: true,
      isScamTypeCorrect: true,
      isFalsePositive: false,
      isFalseNegative: false,
      dnaTruePositives: 1,
      dnaFalsePositives: 0,
      dnaFalseNegatives: 0,
      dnaPrecision: 1,
      dnaRecall: 1,
      dnaF1: 1,
      aiConfidence: null,
      extractionConfidence: null,
      isExtractionFailure: false,
      isIndeterminate: false,
    },
    // 2. Scam: Missed as low (FN, incorrect risk, incorrect scam type)
    {
      id: 'MOCK-002',
      title: 'Scam FN',
      category: 'scam',
      dialect: 'yemeni',
      expectedRiskCategory: 'high',
      actualRiskCategory: 'low',
      riskScore: 0,
      expectedScamType: 'DELIVERY_SCAM',
      actualScamType: 'UNKNOWN',
      expectedDnaFeatures: ['urgency'],
      actualDnaFeatures: [],
      isRiskCategoryCorrect: false,
      isScamTypeCorrect: false,
      isFalsePositive: false,
      isFalseNegative: true,
      dnaTruePositives: 0,
      dnaFalsePositives: 0,
      dnaFalseNegatives: 1,
      dnaPrecision: 0,
      dnaRecall: 0,
      dnaF1: 0,
      aiConfidence: null,
      extractionConfidence: null,
      isExtractionFailure: false,
      isIndeterminate: false,
    },
    // 3. Scam: Unextracted Screenshot (Indeterminate, must NOT count as correct or clean negative)
    {
      id: 'MOCK-003',
      title: 'Scam Indeterminate Screenshot',
      category: 'scam',
      dialect: 'msa',
      expectedRiskCategory: 'high',
      actualRiskCategory: 'low',
      riskScore: 0,
      expectedScamType: 'ACCOUNT_TAKEOVER',
      actualScamType: 'UNKNOWN',
      expectedDnaFeatures: ['otp_request'],
      actualDnaFeatures: [],
      isRiskCategoryCorrect: false,
      isScamTypeCorrect: false,
      isFalsePositive: false,
      isFalseNegative: false, // Marked indeterminate, not ordinary FN
      dnaTruePositives: 0,
      dnaFalsePositives: 0,
      dnaFalseNegatives: 1,
      dnaPrecision: 0,
      dnaRecall: 0,
      dnaF1: 0,
      aiConfidence: null,
      extractionConfidence: null,
      isExtractionFailure: true,
      isIndeterminate: true,
    },
    // 4. Legitimate: Clean benign (TN, correct risk, UNKNOWN matches UNKNOWN)
    {
      id: 'MOCK-004',
      title: 'Legit TN',
      category: 'legitimate',
      dialect: 'msa',
      expectedRiskCategory: 'low',
      actualRiskCategory: 'low',
      riskScore: 0,
      expectedScamType: 'UNKNOWN',
      actualScamType: 'UNKNOWN',
      expectedDnaFeatures: [],
      actualDnaFeatures: [],
      isRiskCategoryCorrect: true,
      isScamTypeCorrect: true,
      isFalsePositive: false,
      isFalseNegative: false,
      dnaTruePositives: 0,
      dnaFalsePositives: 0,
      dnaFalseNegatives: 0,
      dnaPrecision: 1,
      dnaRecall: 1,
      dnaF1: 1,
      aiConfidence: null,
      extractionConfidence: null,
      isExtractionFailure: false,
      isIndeterminate: false,
    },
    // 5. Legitimate: Flagged as suspicious (FP, incorrect risk)
    {
      id: 'MOCK-005',
      title: 'Legit FP',
      category: 'legitimate',
      dialect: 'gulf',
      expectedRiskCategory: 'low',
      actualRiskCategory: 'suspicious',
      riskScore: 35,
      expectedScamType: 'UNKNOWN',
      actualScamType: 'UNKNOWN',
      expectedDnaFeatures: [],
      actualDnaFeatures: ['urgency'],
      isRiskCategoryCorrect: false,
      isScamTypeCorrect: true,
      isFalsePositive: true,
      isFalseNegative: false,
      dnaTruePositives: 0,
      dnaFalsePositives: 1,
      dnaFalseNegatives: 0,
      dnaPrecision: 0,
      dnaRecall: 0,
      dnaF1: 0,
      aiConfidence: null,
      extractionConfidence: null,
      isExtractionFailure: false,
      isIndeterminate: false,
    },
    // 6. Legitimate: Unextracted Screenshot (Indeterminate, must NOT count as correct TN)
    {
      id: 'MOCK-006',
      title: 'Legit Indeterminate Screenshot',
      category: 'legitimate',
      dialect: 'msa',
      expectedRiskCategory: 'low',
      actualRiskCategory: 'low',
      riskScore: 0,
      expectedScamType: 'UNKNOWN',
      actualScamType: 'UNKNOWN',
      expectedDnaFeatures: [],
      actualDnaFeatures: [],
      isRiskCategoryCorrect: false,
      isScamTypeCorrect: false,
      isFalsePositive: false,
      isFalseNegative: false,
      dnaTruePositives: 0,
      dnaFalsePositives: 0,
      dnaFalseNegatives: 0,
      dnaPrecision: 1,
      dnaRecall: 1,
      dnaF1: 1,
      aiConfidence: null,
      extractionConfidence: null,
      isExtractionFailure: true,
      isIndeterminate: true,
    },
  ];

  it('1. calculates Confusion Matrix accurately with indeterminate breakdown', () => {
    const matrix = calculateConfusionMatrix(MOCK_CASE_RESULTS);
    assert.strictEqual(matrix.truePositives, 1);
    assert.strictEqual(matrix.falseNegatives, 1);
    assert.strictEqual(matrix.scamIndeterminate, 1);
    assert.strictEqual(matrix.trueNegatives, 1);
    assert.strictEqual(matrix.falsePositives, 1);
    assert.strictEqual(matrix.legitimateIndeterminate, 1);
    assert.strictEqual(matrix.totalIndeterminate, 2);
  });

  it('2. calculates Risk Metrics (coverage-adjusted vs. determinate accuracy)', () => {
    const matrix = calculateConfusionMatrix(MOCK_CASE_RESULTS);
    const risk = calculateRiskMetrics(MOCK_CASE_RESULTS, matrix);

    assert.strictEqual(risk.totalCases, 6);
    assert.strictEqual(risk.indeterminateCasesCount, 2);
    assert.strictEqual(risk.determinateCasesCount, 4);

    // Total correct: MOCK-001 (TP) and MOCK-004 (TN) = 2.
    // Coverage-adjusted: 2 / 6 = 0.333
    assert.strictEqual(risk.coverageAdjustedAccuracy, 0.333);

    // Determinate: 2 / 4 = 0.500
    assert.strictEqual(risk.determinateRiskAccuracy, 0.5);
  });

  it('3. calculates Legitimate Metrics (FPR = FP / (TN + FP))', () => {
    const matrix = calculateConfusionMatrix(MOCK_CASE_RESULTS);
    const legit = calculateLegitimateMetrics(MOCK_CASE_RESULTS, matrix);

    assert.strictEqual(legit.totalLegitimateCases, 3);
    assert.strictEqual(legit.trueNegativesCount, 1);
    assert.strictEqual(legit.falsePositivesCount, 1);
    assert.strictEqual(legit.legitimateIndeterminateCount, 1);

    // FPR = FP / (TN + FP) = 1 / (1 + 1) = 0.500 (NOT 1 / 3 = 0.333)
    assert.strictEqual(legit.falsePositiveRate, 0.5);
    assert.strictEqual(legit.legitimateDeterminateAccuracy, 0.5);

    // Coverage-adjusted accuracy: TN / Total = 1 / 3 = 0.333
    assert.strictEqual(legit.legitimateAccuracy, 0.333);
    assert.strictEqual(legit.legitimateIndeterminateRate, 0.333);
  });

  it('4. calculates Scam Metrics (determinate FNR vs. miss rate including indeterminate)', () => {
    const matrix = calculateConfusionMatrix(MOCK_CASE_RESULTS);
    const scam = calculateScamMetrics(MOCK_CASE_RESULTS, matrix);

    assert.strictEqual(scam.totalScamCases, 3);
    assert.strictEqual(scam.truePositivesCount, 1);
    assert.strictEqual(scam.falseNegativesCount, 1);
    assert.strictEqual(scam.scamIndeterminateCount, 1);

    // Determinate Recall: TP / (TP + FN) = 1 / 2 = 0.500
    assert.strictEqual(scam.scamDeterminateDetectionRate, 0.5);

    // Determinate FNR: FN / (TP + FN) = 1 / 2 = 0.500
    assert.strictEqual(scam.scamDeterminateFNR, 0.5);

    // Miss rate including indeterminate: (FN + Indet) / Total = (1 + 1) / 3 = 0.667
    assert.strictEqual(scam.scamMissRateIncludingIndeterminate, 0.667);
  });

  it('5. calculates Scam-Type Metrics and isolates UNKNOWN from inflating scam accuracy', () => {
    const scamType = calculateScamTypeMetrics(MOCK_CASE_RESULTS);

    // Determinate Scams: 2 (MOCK-001, MOCK-002). MOCK-001 matches BANK_IMPERSONATION.
    // 1 / 2 = 0.500
    assert.strictEqual(scamType.scamTypeScamOnlyDeterminateAccuracy, 0.5);

    // Total Scams: 3. Correct non-unknown: 1.
    // 1 / 3 = 0.333
    assert.strictEqual(scamType.scamTypeScamOnlyCoverageAdjustedAccuracy, 0.333);
    assert.strictEqual(scamType.scamTypeScamOnlyIndeterminateRate, 0.333);

    // All Cases: matches on MOCK-001 (BANK_IMPERSONATION) and MOCK-004, MOCK-005 (UNKNOWN) = 3 / 6 = 0.500
    assert.strictEqual(scamType.scamTypeAllCasesCoverageAdjusted, 0.5);
  });

  it('6. safe divide-by-zero handling in precision, recall, and F1', () => {
    assert.strictEqual(calculatePrecision(0, 0), 0);
    assert.strictEqual(calculateRecall(0, 0), 0);
    assert.strictEqual(calculateF1(0, 0), 0);

    assert.strictEqual(calculatePrecision(5, 0), 1.0);
    assert.strictEqual(calculateRecall(5, 0), 1.0);
    assert.strictEqual(calculateF1(1.0, 1.0), 1.0);
  });
});
