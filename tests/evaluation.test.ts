/**
 * HARIS (حارس) — Phase 6A: Evaluation Dataset & Benchmark Regression Tests
 *
 * Verifies that the versioned evaluation dataset satisfies all integrity,
 * distribution, privacy, and schema constraints.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import { EVALUATION_DATASET } from '../evaluation/dataset';
import { SCREENSHOT_FIXTURES } from '../evaluation/fixtures/screenshots';
import { SCAM_TYPES, SCAM_DNA_FEATURES } from '../lib/analysis/taxonomy';

describe('HARIS Phase 6A: Evaluation Dataset Integrity & Invariants', () => {
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

      // At least one input modality must be present
      const hasText = typeof item.input.text === 'string' && item.input.text.length > 0;
      const hasUrl = typeof item.input.url === 'string' && item.input.url.length > 0;
      const hasScreenshot = Boolean(item.input.screenshot?.data);
      assert.ok(
        hasText || hasUrl || hasScreenshot,
        `Item ${item.id} must have at least text, url, or screenshot`
      );

      // Expected risk level
      assert.ok(
        ['low', 'suspicious', 'high'].includes(item.expectedRiskCategory),
        `Item ${item.id} invalid expectedRiskCategory: ${item.expectedRiskCategory}`
      );

      // Expected scam type must be in SCAM_TYPES
      assert.ok(
        (SCAM_TYPES as readonly string[]).includes(item.expectedScamType),
        `Item ${item.id} invalid expectedScamType: ${item.expectedScamType}`
      );

      // Expected DNA features must be in SCAM_DNA_FEATURES
      for (const feat of item.expectedDnaFeatures) {
        assert.ok(
          (SCAM_DNA_FEATURES as readonly string[]).includes(feat),
          `Item ${item.id} invalid expectedDnaFeature: ${feat}`
        );
      }
    }
  });

  it('5. screenshot fixtures set covers all required test modalities', () => {
    const fixtureKeys = Object.keys(SCREENSHOT_FIXTURES);
    assert.ok(fixtureKeys.length >= 7, `Expected at least 7 screenshot fixtures, got ${fixtureKeys.length}`);

    for (const key of fixtureKeys) {
      const fix = SCREENSHOT_FIXTURES[key];
      assert.ok(fix.id);
      assert.ok(fix.name);
      assert.ok(fix.mimeType.startsWith('image/'));
      assert.ok(fix.dataUrl.startsWith('data:image/'));
      assert.ok(fix.simulatedVisualDescription);
    }
  });
});
