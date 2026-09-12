/**
 * HARIS (حارس) — Adversarial Red-Team Test Suite (Phase 6B)
 *
 * Verifies:
 * 1. Red-Team dataset structure, 16 taxonomy categories coverage, and schema invariants.
 * 2. Comprehensive Zero-PII safety scan across all text, URLs, descriptions, and rationales.
 * 3. Evaluator logic: failure mode classification, severity tagging, and evidence integrity violations.
 * 4. Production and baseline benchmark isolation (0 mutations to baseline or production code).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import * as crypto from 'crypto';
import { RED_TEAM_DATASET } from '../evaluation/red_team/dataset';
import { RED_TEAM_CATEGORIES, RedTeamTaxonomyCategory } from '../evaluation/red_team/types';
import { normalizeForContainment, calculateRedTeamSummary, evaluateRedTeamItem } from '../evaluation/red_team/evaluator';
import { EVALUATION_DATASET } from '../evaluation/dataset';
import { SCAM_TYPES, SCAM_DNA_FEATURES } from '../lib/analysis/taxonomy';

describe('HARIS Phase 6B: Red-Team Dataset Invariants & Taxonomy Coverage', () => {
  it('1. contains exactly 48 attack cases (3 cases per category)', () => {
    assert.strictEqual(RED_TEAM_DATASET.length, 48, `Expected 48 cases, got ${RED_TEAM_DATASET.length}`);
  });

  it('2. covers all 16 threat taxonomy categories from RED_TEAM_TAXONOMY.md with at least 3 cases each', () => {
    const categoryCounts: Record<string, number> = {};
    for (const item of RED_TEAM_DATASET) {
      categoryCounts[item.taxonomyCategory] = (categoryCounts[item.taxonomyCategory] || 0) + 1;
    }

    for (const cat of RED_TEAM_CATEGORIES) {
      const count = categoryCounts[cat] || 0;
      assert.ok(count >= 3, `Category '${cat}' has fewer than 3 cases (${count})`);
    }

    assert.strictEqual(
      Object.keys(categoryCounts).length,
      16,
      'Expected exactly 16 categories represented'
    );
  });

  it('3. covers diverse Arab dialects including Yemeni, Gulf, Egyptian, Arabizi, and broken Arabic', () => {
    const dialects = new Set<string>(RED_TEAM_DATASET.map((c) => c.dialect));
    assert.ok(dialects.has('msa'), 'Missing MSA cases');
    assert.ok(dialects.has('yemeni'), 'Missing Yemeni cases');
    assert.ok(dialects.has('gulf'), 'Missing Gulf cases');
    assert.ok(dialects.has('egyptian'), 'Missing Egyptian cases');
    assert.ok(dialects.has('mixed_en'), 'Missing mixed English/Arabic cases');
    assert.ok(dialects.has('arabizi'), 'Missing Arabizi cases');
    assert.ok(dialects.has('broken_arabic'), 'Missing broken Arabic cases');

    const yemeniCases = RED_TEAM_DATASET.filter((c) => c.dialect === 'yemeni');
    assert.ok(yemeniCases.length >= 6, `Expected at least 6 Yemeni cases, got ${yemeniCases.length}`);
  });

  it('4. guarantees unique case IDs and valid schemas', () => {
    const idSet = new Set<string>();
    for (const item of RED_TEAM_DATASET) {
      assert.ok(item.id, 'Item must have an ID');
      assert.strictEqual(idSet.has(item.id), false, `Duplicate ID detected: ${item.id}`);
      idSet.add(item.id);

      assert.ok(item.title, `Item ${item.id} missing title`);
      assert.ok(item.description, `Item ${item.id} missing description`);
      assert.ok(item.rationale, `Item ${item.id} missing rationale`);

      const hasText = typeof item.input.text === 'string' && item.input.text.length > 0;
      const hasUrl = typeof item.input.url === 'string' && item.input.url.length > 0;
      const hasScreenshot = Boolean(item.input.screenshot?.base64);
      assert.ok(hasText || hasUrl || hasScreenshot, `Item ${item.id} must have text, url, or screenshot`);

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
});

describe('HARIS Phase 6B: Comprehensive Dataset Safety Guardrail (Zero PII)', () => {
  it('enforces that no raw phone numbers, OTP literals, or account IDs exist in any red-team text field', () => {
    const rawPhoneRegex = /(?:\+?96[67]\d{7,9}|0096[67]\d{7,9}|05\d{8}|01[0125]\d{8}|00\d{10,14})/;
    const rawOtpLiteralRegex = /(?:رمز التحقق(?: الخاص بك)?(?: هو)?:\s*\d{4,8})/;
    const rawAccountLiteralRegex = /(?:محفظة(?:\s+\w+)?\s+رقم\s+\d{6,})/;

    for (const item of RED_TEAM_DATASET) {
      const fieldsToScan: Record<string, string> = {
        title: item.title,
        description: item.description,
        rationale: item.rationale,
        text: item.input.text || '',
        url: item.input.url || '',
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
  });
});

describe('HARIS Phase 6B: Evaluator Normalization & Evidence Integrity Checks', () => {
  it('1. correctly normalizes Arabic text by stripping diacritics, tatweel, and normalizing alif', () => {
    const raw = 'عـَزِيـزِي الْعَمِيلُ أَرْسِلْ';
    const normalized = normalizeForContainment(raw);
    assert.strictEqual(normalized, 'عزيزي العميل ارسل');
  });

  it('2. correctly detects evidence integrity violations on forbidden DNA features', async () => {
    // RED-001 has forbiddenDnaFeatures: ['impersonation']
    const item = RED_TEAM_DATASET.find((c) => c.id === 'RED-001');
    assert.ok(item);
    assert.ok(item.forbiddenDnaFeatures?.includes('impersonation'));

    const result = await evaluateRedTeamItem(item);
    assert.strictEqual(result.expectedRiskCategory, 'low');
    // Actual risk on RED-001 should be low, and should NOT trigger impersonation
    assert.strictEqual(result.isRiskCategoryCorrect, true);
    assert.strictEqual(result.actualDnaFeatures.includes('impersonation'), false);
    assert.strictEqual(result.evidenceIntegrityViolations.length, 0);
  });

  it('3. computes aggregate red-team summary metrics accurately', () => {
    const mockCase = {
      id: 'MOCK-RED-1',
      title: 'Mock Case',
      taxonomyCategory: 'brand_mention_no_impersonation' as RedTeamTaxonomyCategory,
      taxonomyCategoryName: '1. Brand Mention Without Impersonation',
      dialect: 'yemeni' as const,
      modality: 'text' as const,
      expectedRiskCategory: 'low' as const,
      actualRiskCategory: 'low' as const,
      riskScore: 0,
      expectedScamType: 'UNKNOWN' as const,
      actualScamType: 'UNKNOWN',
      expectedDnaFeatures: [],
      actualDnaFeatures: [],
      isRiskCategoryCorrect: true,
      isScamTypeCorrect: true,
      isFalsePositive: false,
      isFalseNegative: false,
      isIndeterminate: false,
      evidenceItemsCount: 0,
      evidenceItems: [],
      uncertainties: [],
      actionableAdvice: [],
      aiConfidence: null,
      extractionConfidence: null,
      failures: [],
      evidenceIntegrityViolations: [],
      hasFailure: false,
    };

    const summary = calculateRedTeamSummary([mockCase], {
      datasetVersion: '1.0.0',
      datasetSha256: 'mocksha',
      runnerVersion: '1.0.0',
      evaluationSourceCommit: 'mockcommit',
      nodeVersion: 'v24',
      pipelineMode: 'test',
      geminiConfigured: false,
    });

    assert.strictEqual(summary.totalCases, 1);
    assert.strictEqual(summary.failedCasesCount, 0);
    assert.strictEqual(summary.overallFailureRate, 0);
    assert.strictEqual(summary.falsePositivesCount, 0);
    assert.strictEqual(summary.falseNegativesCount, 0);
  });
});

describe('HARIS Phase 6B: Baseline Benchmark Isolation Guarantee', () => {
  it('1. baseline 70-case dataset remains completely unmodified', () => {
    assert.strictEqual(EVALUATION_DATASET.length, 70, 'Baseline dataset must remain exactly 70 cases');
    const expectedSha256 = '4e82b82e4d4822921cf8c2ee70b39bc51ed9e069694d721fb065bbf7d76be6c8';
    const currentSha256 = crypto
      .createHash('sha256')
      .update(JSON.stringify(EVALUATION_DATASET))
      .digest('hex');
    assert.strictEqual(
      currentSha256,
      expectedSha256,
      'Baseline dataset SHA-256 must match approved Phase 6A.2 baseline hash exactly'
    );
  });
});
