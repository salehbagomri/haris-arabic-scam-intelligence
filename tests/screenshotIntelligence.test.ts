/**
 * HARIS (حارس) — Phase 4B Screenshot Intelligence Tests
 *
 * Validates multimodal OCR/Vision extraction, passive URL routing,
 * evidence grounding, anti-hallucination, brand contradiction synergy,
 * failure recovery, and bounded visual score heuristics.
 *
 * Scenarios Tested:
 * A. Arabic scam screenshot (bank impersonation + suspicious link)
 * B. Legitimate security warning screenshot (negation preserved)
 * C. Yemeni / regional context screenshot (Kuraimi / M-Flous)
 * D. Arabic + English mixed screenshot
 * E. Screenshot with URL in image -> passive URL analyzer runs
 * F. Multiple URLs extracted from image
 * G. Visual impersonation cautious language & bounded score
 * H. Malformed vision output & Zod rejection
 * I. Vision failure fallback behavior
 * J. Empty / unreadable screenshot structured failure
 * K. Oversized image and output boundary enforcement
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  parseAndValidateVisionOutput,
  analyzeUnified,
  validateImageConstraints,
  ScreenshotExtractionData,
  VISION_CONFIG,
} from '../lib/vision';
import { GeminiSemanticAnalysis } from '../lib/ai';
import { DEFAULT_RISK_WEIGHTS } from '../lib/config/weights';

describe('HARIS Phase 4B: Screenshot Intelligence Tests', () => {
  const dummyBuffer = Buffer.from('fake-png-screenshot-bytes-data');

  // =========================================================================
  // Test A — Arabic Scam Screenshot
  // =========================================================================
  describe('Test A — Arabic Scam Screenshot', () => {
    it('extracts text, URL, and visible entities; feeds passive URL analyzer and preserves provenance', async () => {
      const mockVisionData: ScreenshotExtractionData = {
        extractedText:
          'عزيزي العميل، تم إيقاف حسابك المصرفي مؤقتاً لأسباب أمنية. يرجى التحقق فوراً عبر الرابط: https://alrajhi.secure-login.xyz/verify لإعادة التفعيل.',
        extractedUrls: ['https://alrajhi.secure-login.xyz/verify'],
        visibleEntities: [
          { type: 'brand_logo', text: 'مصرف الراجحي', confidence: 0.95 },
          { type: 'button_cta', text: 'إعادة التفعيل', confidence: 0.9 },
        ],
        visualSignals: [
          {
            type: 'impersonation_visual',
            description: 'تُظهر الصورة عناصر تشبه شعار وهوية مصرف الراجحي',
            evidence: 'مصرف الراجحي',
            severity: 'high',
          },
          {
            type: 'fake_security_warning',
            description: 'إشعار تعليق أمني لإثارة الذعر',
            evidence: 'تم إيقاف حسابك المصرفي',
            severity: 'high',
          },
        ],
        uncertainties: [],
        extractionConfidence: 0.94,
      };

      const mockSemanticData: GeminiSemanticAnalysis = {
        interpretation:
          'محاولة احتيال هندسة اجتماعية وانتحال لصفة مصرف الراجحي بهدف استدراج الضحية لموقع مشبوه.',
        scamTypeCandidates: [{ type: 'BANK_IMPERSONATION', confidence: 0.95 }],
        semanticSignals: [
          {
            type: 'انتحال مصرفي',
            description: 'ادعاء صفة البنك لاستدراج بيانات الحساب',
            evidence: 'تم إيقاف حسابك المصرفي',
            severity: 'high',
          },
        ],
        psychologicalTactics: [
          {
            type: 'إثارة الخوف',
            description: 'التهديد بتعليق الحساب لإرباك الضحية',
            evidence: 'تم إيقاف حسابك المصرفي مؤقتاً لأسباب أمنية',
          },
        ],
        scamDnaCandidates: [
          { feature: 'impersonation', evidence: 'مصرف الراجحي', confidence: 0.95 },
          { feature: 'threat_language', evidence: 'تم إيقاف حسابك المصرفي', confidence: 0.9 },
        ],
        aiConfidence: 0.93,
        uncertainties: [],
      };

      // Mock Gemini Client responding to both vision and text calls
      const mockClient = {
        models: {
          generateContent: async (req: { contents: Array<{ parts: Array<{ text?: string; inlineData?: unknown }> }> }) => {
            const hasInlineData = req.contents[0].parts.some((p) => p.inlineData !== undefined);
            if (hasInlineData) {
              return { text: JSON.stringify(mockVisionData) };
            }
            return { text: JSON.stringify(mockSemanticData) };
          },
        },
      };

      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: mockClient as any }
      );

      // 1. Risk assessment should be High
      assert.strictEqual(result.riskLevel, 'high');
      assert.ok(result.riskScore >= 70);

      // 2. Scam type resolved to BANK_IMPERSONATION
      assert.strictEqual(result.scamType, 'BANK_IMPERSONATION');

      // 3. Passive URL analysis correctly flagged subdomain brand spoofing
      assert.strictEqual(result.deterministicResult.urlResults.length, 1);
      const urlFinding = result.deterministicResult.urlResults[0];
      assert.strictEqual(urlFinding.brandSpoofing.detected, true);
      assert.strictEqual(urlFinding.brandSpoofing.brandName, 'مصرف الراجحي');

      // 4. Evidence provenance preserved across all categories
      const detEvidence = result.evidence.filter((e) => e.provenance === 'deterministic');
      const aiEvidence = result.evidence.filter((e) => e.provenance === 'ai');
      const ocrEvidence = result.evidence.filter((e) => e.provenance === 'ocr');
      const brandContradiction = result.evidence.find((e) => e.title.includes('تعارض الهوية البصرية'));

      assert.ok(detEvidence.length > 0, 'Expected deterministic evidence from passive URL analyzer');
      assert.ok(aiEvidence.length > 0, 'Expected AI semantic evidence');
      assert.ok(ocrEvidence.length > 0, 'Expected OCR visible entities evidence');
      assert.ok(brandContradiction, 'Expected synergistic brand contradiction evidence item');

      // 5. Visual data populated
      assert.ok(result.visualExtraction);
      assert.strictEqual(result.visualSignals?.length, 2);
    });
  });

  // =========================================================================
  // Test B — Legitimate Security Warning
  // =========================================================================
  describe('Test B — Legitimate Security Warning', () => {
    it('clause-level negation in extracted text prevents false positive OTP request signal', async () => {
      const mockVisionData: ScreenshotExtractionData = {
        extractedText:
          'تنبيه أمني من البنك: لا تشارك رمز التحقق لمرة واحدة OTP أو كلمة المرور مع أي شخص.',
        extractedUrls: [],
        visibleEntities: [],
        visualSignals: [],
        uncertainties: [],
        extractionConfidence: 0.95,
      };

      const mockSemanticData: GeminiSemanticAnalysis = {
        interpretation: 'رسالة توعوية تحذر من مشاركة الرموز السرية.',
        scamTypeCandidates: [{ type: 'UNKNOWN', confidence: 0.1 }],
        semanticSignals: [],
        psychologicalTactics: [],
        scamDnaCandidates: [],
        aiConfidence: 0.95,
        uncertainties: [],
      };

      const mockClient = {
        models: {
          generateContent: async (req: { contents: Array<{ parts: Array<{ inlineData?: unknown }> }> }) => {
            const isVision = req.contents[0].parts.some((p) => p.inlineData !== undefined);
            return { text: JSON.stringify(isVision ? mockVisionData : mockSemanticData) };
          },
        },
      };

      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: mockClient as any }
      );

      // Score must remain low
      assert.strictEqual(result.riskLevel, 'low');
      assert.ok(result.riskScore <= 15);
      // Crucial: OTP request feature must NOT be triggered
      assert.strictEqual(result.detectedFeatures.includes('otp_request'), false);
    });
  });

  // =========================================================================
  // Test C — Yemeni / Regional Context
  // =========================================================================
  describe('Test C — Yemeni / Regional Context', () => {
    it('correctly handles Yemeni colloquial dialect and local payment services', async () => {
      const mockVisionData: ScreenshotExtractionData = {
        extractedText:
          'يا خبير حسابك في بنك الكريمي موقف، حول رسوم التجديد عبر خدمة ام فلوس وافتح الحوالة فوراً.',
        extractedUrls: [],
        visibleEntities: [
          { type: 'brand_logo', text: 'بنك الكريمي', confidence: 0.88 },
        ],
        visualSignals: [
          {
            type: 'suspicious_payment_prompt',
            description: 'مطالبة بسداد رسوم عبر خدمة تحويل محلية',
            evidence: 'حول رسوم التجديد',
            severity: 'high',
          },
        ],
        uncertainties: [],
        extractionConfidence: 0.91,
      };

      const mockSemanticData: GeminiSemanticAnalysis = {
        interpretation:
          'رسالة انتحال لخدمة بنك الكريمي اليمني ومطالبة بتحويل مالي عبر خدمة إم فلوس المحلية.',
        scamTypeCandidates: [{ type: 'BANK_IMPERSONATION', confidence: 0.89 }],
        semanticSignals: [
          {
            type: 'مطالبة مالية غير موثوقة',
            description: 'طلب تحويل أموال لتجديد الحساب',
            evidence: 'حول رسوم التجديد',
            severity: 'high',
          },
        ],
        psychologicalTactics: [],
        scamDnaCandidates: [
          { feature: 'suspicious_payment_request', evidence: 'حول رسوم التجديد', confidence: 0.9 },
        ],
        aiConfidence: 0.9,
        uncertainties: [],
      };

      const mockClient = {
        models: {
          generateContent: async (req: { contents: Array<{ parts: Array<{ inlineData?: unknown }> }> }) => {
            const isVision = req.contents[0].parts.some((p) => p.inlineData !== undefined);
            return { text: JSON.stringify(isVision ? mockVisionData : mockSemanticData) };
          },
        },
      };

      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/jpeg',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: mockClient as any }
      );

      assert.ok(result.detectedFeatures.includes('suspicious_payment_request'));
      assert.ok(result.interpretation.includes('الكريمي'));
      assert.strictEqual(result.visualSignals?.length, 1);
    });
  });

  // =========================================================================
  // Test D — Arabic + English Mixed Language
  // =========================================================================
  describe('Test D — Arabic + English Mixed Language', () => {
    it('preserves mixed-language text during visual extraction and downstream analysis', async () => {
      const mockVisionData: ScreenshotExtractionData = {
        extractedText: 'Your account will be locked. Verify الآن باستخدام OTP عبر الرابط.',
        extractedUrls: [],
        visibleEntities: [
          { type: 'button_cta', text: 'Verify الآن', confidence: 0.95 },
        ],
        visualSignals: [
          {
            type: 'urgency_visual',
            description: 'استعجال باللغة الإنجليزية والعربية',
            evidence: 'Your account will be locked',
            severity: 'medium',
          },
        ],
        uncertainties: [],
        extractionConfidence: 0.92,
      };

      const mockSemanticData: GeminiSemanticAnalysis = {
        interpretation: 'رسالة مزدوجة اللغة تهدد بإغلاق الحساب.',
        scamTypeCandidates: [{ type: 'BANK_IMPERSONATION', confidence: 0.85 }],
        semanticSignals: [],
        psychologicalTactics: [],
        scamDnaCandidates: [
          { feature: 'threat_language', evidence: 'Your account will be locked', confidence: 0.88 },
        ],
        aiConfidence: 0.9,
        uncertainties: [],
      };

      const mockClient = {
        models: {
          generateContent: async (req: { contents: Array<{ parts: Array<{ inlineData?: unknown }> }> }) => {
            const isVision = req.contents[0].parts.some((p) => p.inlineData !== undefined);
            return { text: JSON.stringify(isVision ? mockVisionData : mockSemanticData) };
          },
        },
      };

      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/webp',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: mockClient as any }
      );

      assert.ok(result.detectedFeatures.includes('threat_language'));
      assert.ok(result.visualExtraction?.extractedText.includes('locked'));
    });
  });

  // =========================================================================
  // Test E — Screenshot with URL in Image
  // =========================================================================
  describe('Test E — Screenshot with URL in Image', () => {
    it('verifies that URLs in visual extraction feed into passive URL analyzer', async () => {
      const mockVisionData: ScreenshotExtractionData = {
        extractedText: 'اضغط على الرابط في الصورة للمطالبة بالجائزة: http://claim-gift.top/win',
        extractedUrls: ['http://claim-gift.top/win'],
        visibleEntities: [],
        visualSignals: [],
        uncertainties: [],
        extractionConfidence: 0.9,
      };

      const mockClient = {
        models: {
          generateContent: async () => ({ text: JSON.stringify(mockVisionData) }),
        },
      };

      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: mockClient as any }
      );

      assert.strictEqual(result.deterministicResult.urlResults.length, 1);
      const urlAnalysis = result.deterministicResult.urlResults[0];
      assert.strictEqual(urlAnalysis.rawUrl, 'http://claim-gift.top/win');
      assert.strictEqual(urlAnalysis.isSuspiciousTld, true);
      assert.ok(urlAnalysis.signals.length > 0);
    });
  });

  // =========================================================================
  // Test F — Multiple URLs Extracted from Image
  // =========================================================================
  describe('Test F — Multiple URLs Extracted from Image', () => {
    it('analyzes all extracted URLs without network activity', async () => {
      const mockVisionData: ScreenshotExtractionData = {
        extractedText: 'بوابة الأخبار وموقع التحقق',
        extractedUrls: [
          'https://legitimate-portal.com/news',
          'http://192.168.1.50/malicious-login',
        ],
        visibleEntities: [],
        visualSignals: [],
        uncertainties: [],
        extractionConfidence: 0.9,
      };

      const mockClient = {
        models: {
          generateContent: async () => ({ text: JSON.stringify(mockVisionData) }),
        },
      };

      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: mockClient as any }
      );

      assert.strictEqual(result.deterministicResult.urlResults.length, 2);
      const ipHostResult = result.deterministicResult.urlResults.find((u) => u.isIpHost);
      assert.ok(ipHostResult, 'Expected raw IP host to be flagged');
    });
  });

  // =========================================================================
  // Test G — Visual Impersonation & Bounded Visual Score
  // =========================================================================
  describe('Test G — Visual Impersonation & Bounded Score', () => {
    it('cautious visual signals alone cannot push clean content into high risk', async () => {
      const mockVisionData: ScreenshotExtractionData = {
        extractedText: 'السلام عليكم أخي، كيف حالك؟ حياك الله.',
        extractedUrls: [],
        visibleEntities: [
          { type: 'brand_logo', text: 'شعار مصرف الراجحي', confidence: 0.8 },
        ],
        visualSignals: [
          {
            type: 'impersonation_visual',
            description: 'The screenshot visually resembles Al Rajhi Bank branding',
            evidence: 'شعار مصرف الراجحي',
            severity: 'medium',
          },
        ],
        uncertainties: [],
        extractionConfidence: 0.85,
      };

      const mockClient = {
        models: {
          generateContent: async () => ({ text: JSON.stringify(mockVisionData) }),
        },
      };

      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: mockClient as any }
      );

      // Score must remain strictly bounded and low (<= DEFAULT_RISK_WEIGHTS.maxVisualScoreContribution)
      assert.strictEqual(result.riskLevel, 'low');
      assert.ok(
        result.riskScore <= DEFAULT_RISK_WEIGHTS.maxVisualScoreContribution,
        `Expected score <= ${DEFAULT_RISK_WEIGHTS.maxVisualScoreContribution}, got ${result.riskScore}`
      );
    });
  });

  // =========================================================================
  // Test H — Malformed Vision Output
  // =========================================================================
  describe('Test H — Malformed Vision Output', () => {
    it('Zod validation rejects malformed JSON and enforces graceful recovery', () => {
      // 1. Broken JSON syntax
      const brokenJson = '{"extractedText": "something", broken...';
      const resBroken = parseAndValidateVisionOutput(brokenJson);
      assert.strictEqual(resBroken.success, false);
      assert.ok(resBroken.error && resBroken.error.includes('Malformed JSON'));

      // 2. Missing required fields
      const invalidSchema = JSON.stringify({
        extractedText: 'just text',
        // missing extractedUrls, visualSignals, extractionConfidence, etc.
      });
      const resSchema = parseAndValidateVisionOutput(invalidSchema);
      assert.strictEqual(resSchema.success, false);
      assert.ok(resSchema.error && resSchema.error.includes('Vision schema validation failed'));
    });
  });

  // =========================================================================
  // Test I — Vision Failure Fallback Behavior
  // =========================================================================
  describe('Test I — Vision Failure Fallback Behavior', () => {
    it('falls back to deterministic analysis when screenshot extraction fails but text is available', async () => {
      // Mock client that fails on vision request
      const failingClient = {
        models: {
          generateContent: async () => {
            throw new Error('Vision service timeout after 15000ms');
          },
        },
      };

      const userText = 'أرسل لي رمز التحقق OTP فوراً لتحديث الحساب.';
      const result = await analyzeUnified(
        {
          text: userText,
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: failingClient as any }
      );

      // Deterministic analysis still completed on text!
      assert.ok(result.detectedFeatures.includes('otp_request'));
      assert.ok(result.riskScore > 0);
      assert.ok(
        result.uncertainties.some((u) => u.includes('timeout') || u.includes('محدودية') || u.includes('Warning') || u.includes('warning') || u.includes('Vision') || u.includes('التحليل الدلالي'))
      );
    });
  });

  // =========================================================================
  // Test J — Empty / Unreadable Screenshot
  // =========================================================================
  describe('Test J — Empty / Unreadable Screenshot', () => {
    it('returns a safe structured failure without crashing when image is 0 bytes', async () => {
      const emptyBuffer = Buffer.from([]);
      const result = await analyzeUnified({
        screenshot: {
          buffer: emptyBuffer,
          mimeType: 'image/png',
        },
      });

      assert.strictEqual(result.riskLevel, 'low');
      assert.strictEqual(result.riskScore, 0);
      assert.strictEqual(result.aiAvailable, false);
      assert.strictEqual(result.isExtractionFailure, true);
      assert.ok(result.interpretation.includes('تعذر استخراج أو قراءة محتوى لقطة الشاشة'));
      assert.ok(!result.interpretation.includes('لم يتم رصد أي مؤشرات احتيال واضحة'));
      assert.ok(result.aiFallbackReason && result.aiFallbackReason.includes('0 bytes'));
      assert.ok(result.uncertainties.some((u) => u.includes('0 bytes')));
      assert.ok(result.actionableAdvice.some((a) => a.includes('لقطة شاشة') || a.includes('نسخ نص')));
    });
  });

  // =========================================================================
  // Test K — Oversized Image & Output Limits
  // =========================================================================
  describe('Test K — Oversized Image & Output Limits', () => {
    it('rejects image payloads exceeding the configured size limit', () => {
      // Create a virtual buffer header that exceeds 10MB
      const hugeBuffer = {
        length: VISION_CONFIG.maxImageSizeBytes + 1024,
      } as Buffer;

      const validation = validateImageConstraints({
        buffer: hugeBuffer,
        mimeType: 'image/png',
      });

      assert.strictEqual(validation.valid, false);
      assert.ok(validation.error && validation.error.includes('exceeds the maximum allowed limit'));
    });

    it('rejects unsupported image MIME types', () => {
      const validation = validateImageConstraints({
        buffer: dummyBuffer,
        mimeType: 'application/pdf',
      });

      assert.strictEqual(validation.valid, false);
      assert.ok(validation.error && validation.error.includes('Unsupported image MIME type'));
    });

    it('rejects oversized model output strings exceeding schema limits', () => {
      const oversizedText = 'أ'.repeat(VISION_CONFIG.maxExtractedTextLength + 5);
      const payload = {
        extractedText: oversizedText,
        extractedUrls: [],
        visibleEntities: [],
        visualSignals: [],
        uncertainties: [],
        extractionConfidence: 0.9,
      };

      const res = parseAndValidateVisionOutput(JSON.stringify(payload));
      assert.strictEqual(res.success, false);
      assert.ok(res.error && res.error.includes('character limit'));
    });
  });

  // =========================================================================
  // Phase 4B Audit Precision Fixes Regression Tests
  // =========================================================================
  describe('Phase 4B Audit Precision Fixes Regression Tests', () => {
    // 1. Screenshot-only extraction failure does not produce a misleading clean/low-risk interpretation
    it('1. screenshot-only extraction failure does not produce a misleading clean/low-risk interpretation', async () => {
      const failingClient = {
        models: {
          generateContent: async () => {
            throw new Error('Vision gateway timeout after 15000ms');
          },
        },
      };

      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: failingClient as any }
      );

      assert.strictEqual(result.isExtractionFailure, true);
      assert.ok(result.interpretation.includes('تعذر استخراج أو قراءة محتوى لقطة الشاشة'));
      assert.ok(!result.interpretation.includes('لم يتم رصد أي مؤشرات احتيال واضحة'));
      assert.ok(result.interpretation.includes('لا يعتبر ذلك مؤشراً على أمان الرسالة'));
    });

    // 2. Failure reason appears in uncertainties
    it('2. failure reason appears in uncertainties', async () => {
      const failingClient = {
        models: {
          generateContent: async () => {
            throw new Error('Connection refused by vision service');
          },
        },
      };

      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: failingClient as any }
      );

      assert.ok(result.uncertainties.some((u) => u.includes('Connection refused by vision service')));
      assert.ok(result.uncertainties.some((u) => u.includes('ولا تعني بأي حال من الأحوال أن الرسالة آمنة')));
    });

    // 3. Failure advice asks for clearer screenshot / pasted text
    it('3. failure advice asks for clearer screenshot/pasted text', async () => {
      const failingClient = {
        models: {
          generateContent: async () => {
            throw new Error('Network reset');
          },
        },
      };

      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: failingClient as any }
      );

      assert.ok(result.actionableAdvice.some((a) => a.includes('لقطة شاشة بدقة أعلى')));
      assert.ok(result.actionableAdvice.some((a) => a.includes('نسخ نص الرسالة')));
    });

    // 4. Text/URL fallback still works
    it('4. text/URL fallback still works when screenshot extraction fails', async () => {
      const failingClient = {
        models: {
          generateContent: async () => {
            throw new Error('Vision service offline');
          },
        },
      };

      const result = await analyzeUnified(
        {
          text: 'عزيزي العميل، تم إيقاف حسابك، أرسل رمز التحقق OTP فوراً.',
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: failingClient as any }
      );

      // Deterministic and semantic text fallback completed successfully
      assert.strictEqual(result.isExtractionFailure, false);
      assert.ok(result.detectedFeatures.includes('otp_request'));
      assert.ok(result.riskScore > 0);
      assert.ok(result.uncertainties.some((u) => u.includes('فشل استخراج لقطة الشاشة')));
    });

    // 5. Quoted visual signal with empty extracted text is rejected
    it('5. quoted visual signal with empty extracted text is rejected as ungrounded', () => {
      const payload = {
        extractedText: '',
        extractedUrls: [],
        visibleEntities: [],
        visualSignals: [
          {
            type: 'urgency_visual',
            description: 'استعجال فوري',
            evidence: 'عبارة مقتبسة "سدد الحساب فوراً لتجنب الإيقاف"',
            severity: 'high',
          },
        ],
        uncertainties: [],
        extractionConfidence: 0.8,
      };

      const res = parseAndValidateVisionOutput(JSON.stringify(payload));
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.data?.visualSignals.length, 0); // Pruned as ungrounded quote!
    });

    // 6. Non-quoted visual observation with empty extracted text remains allowed
    it('6. non-quoted visual observation with empty extracted text remains allowed', () => {
      const payload = {
        extractedText: '',
        extractedUrls: [],
        visibleEntities: [],
        visualSignals: [
          {
            type: 'impersonation_visual',
            description: 'The screenshot visually resembles Saudi Post (SPL) branding and color scheme',
            evidence: 'شعار البريد السعودي ودرجات اللون الأزرق والأخضر',
            severity: 'medium',
          },
        ],
        uncertainties: [],
        extractionConfidence: 0.85,
      };

      const res = parseAndValidateVisionOutput(JSON.stringify(payload));
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.data?.visualSignals.length, 1);
      assert.strictEqual(res.data?.visualSignals[0].type, 'impersonation_visual');
    });

    // 7. Valid quoted signal grounded in extracted text still passes
    it('7. valid quoted signal grounded in extracted text still passes', () => {
      const payload = {
        extractedText: 'تنبيه: تم تعليق بطاقتك المصرفية، يرجى التفعيل الآن عبر الرابط.',
        extractedUrls: [],
        visibleEntities: [],
        visualSignals: [
          {
            type: 'fake_security_warning',
            description: 'تحذير تعليق البطاقة لإثارة القلق',
            evidence: 'يظهر نص "تم تعليق بطاقتك المصرفية"',
            severity: 'high',
          },
        ],
        uncertainties: [],
        extractionConfidence: 0.95,
      };

      const res = parseAndValidateVisionOutput(JSON.stringify(payload));
      assert.strictEqual(res.success, true);
      assert.strictEqual(res.data?.visualSignals.length, 1);
      assert.strictEqual(res.data?.visualSignals[0].type, 'fake_security_warning');
    });
  });
});
