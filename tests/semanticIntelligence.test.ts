/**
 * HARIS (حارس) — Phase 4A Semantic Intelligence Tests
 *
 * Comprehensive test suite covering requirements A through J:
 * A. Obvious scam
 * B. Legitimate security warning
 * C. Social engineering without obvious keywords
 * D. Yemeni / colloquial Arabic
 * E. Arabic + English mixed language
 * F. Arabizi transliteration
 * G. Malformed AI response & graceful recovery
 * H. Gemini unavailable / fallback behavior
 * I. AI confidence separation from risk score
 * J. Evidence provenance transparency
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  parseAndValidateSemanticOutput,
  cleanJsonFence,
  fuseEvidenceAndAssess,
  GeminiSemanticAnalysis,
  analyzeSemantics,
  analyzeWithSemanticIntelligence,
  isEvidenceGrounded,
} from '../lib/ai';
import { analyzeDeterministic } from '../lib/analysis';
import { DEFAULT_RISK_WEIGHTS } from '../lib/config/weights';

describe('HARIS Phase 4A: Gemini Semantic Intelligence & Evidence Fusion Tests', () => {
  // =========================================================================
  // G. Malformed AI Response & Schema Parser Resilience
  // =========================================================================
  describe('Parser & Schema Resilience (Requirement G)', () => {
    it('should strip markdown code fences correctly', () => {
      const raw = '```json\n{"test": 1}\n```';
      assert.strictEqual(cleanJsonFence(raw), '{"test": 1}');
    });

    it('should fail gracefully on invalid JSON syntax without throwing', () => {
      const brokenJson = '{"interpretation": "something", broken...';
      const res = parseAndValidateSemanticOutput(brokenJson, 'original text', 'normalized text');

      assert.strictEqual(res.success, false);
      assert.ok(res.error && res.error.includes('Malformed JSON'));
    });

    it('should reject schemas missing required fields', () => {
      const missingFields = JSON.stringify({
        interpretation: 'test',
        // missing scamTypeCandidates, uncertainties, etc.
      });
      const res = parseAndValidateSemanticOutput(missingFields, 'test text', 'test text');

      assert.strictEqual(res.success, false);
      assert.ok(res.error && res.error.includes('Zod schema validation failed'));
    });

    it('should prune fabricated evidence not present in source text (Anti-Hallucination)', () => {
      const mockPayload: GeminiSemanticAnalysis = {
        interpretation: 'رسالة مشبوهة',
        scamTypeCandidates: [{ type: 'BANK_IMPERSONATION', confidence: 0.9 }],
        semanticSignals: [
          {
            type: 'دليل حقيقي',
            description: 'وصف',
            evidence: 'الرقم السري',
            severity: 'high',
          },
          {
            type: 'دليل ملفق',
            description: 'هذا الدليل غير موجود إطلاقاً في الرسالة',
            evidence: 'عبارة وهمية لم يكتبها المستخدم بتاتاً',
            severity: 'high',
          },
        ],
        psychologicalTactics: [],
        scamDnaCandidates: [
          {
            feature: 'credential_request',
            evidence: 'الرقم السري',
            confidence: 0.9,
          },
          {
            feature: 'financial_lure',
            evidence: 'ربحت مليون دولار لم يذكرها أحد',
            confidence: 0.9,
          },
        ],
        aiConfidence: 0.85,
        uncertainties: [],
      };

      const originalText = 'أدخل الرقم السري لتأكيد حسابك.';
      const res = parseAndValidateSemanticOutput(
        JSON.stringify(mockPayload),
        originalText,
        originalText
      );

      assert.strictEqual(res.success, true);
      assert.ok(res.data);
      // The hallucinated signal and DNA candidate must be pruned
      assert.strictEqual(res.data.semanticSignals.length, 1);
      assert.strictEqual(res.data.semanticSignals[0].evidence, 'الرقم السري');
      assert.strictEqual(res.data.scamDnaCandidates.length, 1);
      assert.strictEqual(res.data.scamDnaCandidates[0].feature, 'credential_request');
    });

    // --- Specific Anti-Hallucination Guard Regression Cases ---
    it('Guard Case 1: exact evidence → accepted', () => {
      const evidence = 'الرمز السري';
      const orig = 'يرجى إدخال الرمز السري لتأكيد الدخول';
      const norm = 'يرجى ادخال الرمز السري لتاكيد الدخول';
      assert.strictEqual(isEvidenceGrounded(evidence, orig, norm), true);
    });

    it('Guard Case 2: Arabic normalization difference (hamza, diacritics, tatweel) → accepted', () => {
      const evidenceWithHamza = 'إيقاف بطاقتك';
      const origWithTashkeel = 'تنبيه: تم إِيْــــقَافُ بَطَاقَتِكَ مؤقتاً';
      const normText = 'تنبيه: تم ايقاف بطاقتك مؤقتا';
      assert.strictEqual(isEvidenceGrounded(evidenceWithHamza, origWithTashkeel, normText), true);

      // Symmetrically: model output without hamza vs source with hamza
      const evidencePlain = 'ايقاف بطاقتك';
      const origHamza = 'تنبيه: تم إيقاف بطاقتك مؤقتاً';
      assert.strictEqual(isEvidenceGrounded(evidencePlain, origHamza, normText), true);
    });

    it('Guard Case 3: fabricated paraphrase → rejected', () => {
      const paraphrase = 'أدخل كود التفعيل لتحديث الحساب';
      const orig = 'يرجى إرسال الرمز الخاص بك لتأكيد الهوية';
      const norm = 'يرجى ارسال الرمز الخاص بك لتاكيد الهويه';
      assert.strictEqual(isEvidenceGrounded(paraphrase, orig, norm), false);
    });

    it('Guard Case 4: partial-token overlap → rejected', () => {
      // 3 of 6 words match disjointly, but the full phrase is fabricated
      const partialEvidence = 'تم إيقاف بطاقتك وسرقة حسابك البنكي';
      const orig = 'عزيزي العميل، تم إيقاف بطاقتك الائتمانية لأسباب أمنية';
      const norm = 'عزيزي العميل، تم ايقاف بطاقتك الائتمانيه لاسباب امنيه';
      assert.strictEqual(isEvidenceGrounded(partialEvidence, orig, norm), false);
    });

    it('Guard Case 5: unrelated phrase with one matching word → rejected', () => {
      const singleWordMatch = 'كلمة المرور';
      const orig = 'هذا مقال إخباري عام عن إدارة المرور العامة في العاصمة';
      const norm = 'هذا مقال اخباري عام عن اداره المرور العامه في العاصمه';
      assert.strictEqual(isEvidenceGrounded(singleWordMatch, orig, norm), false);
    });

    it('should reject oversized model outputs exceeding Zod schema boundaries', () => {
      const baseValid = {
        interpretation: 'تفسير صالح',
        scamTypeCandidates: [{ type: 'BANK_IMPERSONATION', confidence: 0.9 }],
        semanticSignals: [],
        psychologicalTactics: [],
        scamDnaCandidates: [],
        aiConfidence: 0.8,
        uncertainties: [],
      };

      // 1. Oversized interpretation (> 2000 chars)
      const oversizedInterpretation = {
        ...baseValid,
        interpretation: 'أ'.repeat(2001),
      };
      const resInterp = parseAndValidateSemanticOutput(JSON.stringify(oversizedInterpretation), 'نص', 'نص');
      assert.strictEqual(resInterp.success, false);
      assert.ok(resInterp.error && resInterp.error.includes('2000'));

      // 2. Oversized evidence (> 500 chars)
      const oversizedEvidence = {
        ...baseValid,
        semanticSignals: [
          {
            type: 'نوع',
            description: 'وصف',
            evidence: 'د'.repeat(501),
            severity: 'high',
          },
        ],
      };
      const resEv = parseAndValidateSemanticOutput(JSON.stringify(oversizedEvidence), 'نص', 'نص');
      assert.strictEqual(resEv.success, false);
      assert.ok(resEv.error && resEv.error.includes('500'));

      // 3. Oversized array (> 20 items)
      const oversizedArray = {
        ...baseValid,
        semanticSignals: Array.from({ length: 21 }, (_, i) => ({
          type: `نوع ${i}`,
          description: `وصف ${i}`,
          evidence: `دليل ${i}`,
          severity: 'low',
        })),
      };
      const resArr = parseAndValidateSemanticOutput(JSON.stringify(oversizedArray), 'نص', 'نص');
      assert.strictEqual(resArr.success, false);
      assert.ok(resArr.error && resArr.error.includes('20'));
    });
  });

  // =========================================================================
  // A. Obvious Scam: Semantic Enrichment without Overriding Deterministic Evidence
  // =========================================================================
  describe('A. Obvious Scam Scenario', () => {
    it('Gemini adds semantic interpretation while deterministic evidence holds priority', () => {
      const text =
        'عزيزي العميل، تم تجميد حسابك البنكي لدى مصرف الراجحي، يرجى الدخول فوراً عبر الرابط https://alrajhi.fake-bank.xyz لتحديث كلمة المرور وإدخال رمز التحقق.';
      const deterministic = analyzeDeterministic({ text });

      const mockAi: GeminiSemanticAnalysis = {
        interpretation:
          'رسالة انتحال صفة مصرفية كلاسيكية تستخدم أسلوب الترهيب بتجميد الحساب لإجبار الضحية على إفشاء بيانات الاعتماد عبر رابط تصيد.',
        scamTypeCandidates: [{ type: 'BANK_IMPERSONATION', confidence: 0.95 }],
        semanticSignals: [
          {
            type: 'استدراج بيانات الدخول عبر التهديد',
            description: 'الربط بين تجميد الحساب وإدخال كلمة المرور',
            evidence: 'لتحديث كلمة المرور',
            severity: 'high',
          },
        ],
        psychologicalTactics: [
          {
            type: 'الخوف والترهيب المالي',
            description: 'إيهام الضحية بتعطيل حسابها لإثارة الذعر ودفعها للتصرف العاجل',
            evidence: 'تم تجميد حسابك البنكي',
          },
        ],
        scamDnaCandidates: [
          { feature: 'impersonation', evidence: 'مصرف الراجحي', confidence: 0.95 },
          { feature: 'credential_request', evidence: 'كلمة المرور', confidence: 0.95 },
          { feature: 'otp_request', evidence: 'رمز التحقق', confidence: 0.95 },
          { feature: 'urgency', evidence: 'فوراً', confidence: 0.9 },
        ],
        aiConfidence: 0.95,
        uncertainties: [],
      };

      const fused = fuseEvidenceAndAssess(deterministic, mockAi, {
        modelUsed: 'gemini-2.5-flash',
      });

      assert.strictEqual(fused.aiAvailable, true);
      assert.strictEqual(fused.riskLevel, 'high');
      assert.strictEqual(fused.scamType, 'BANK_IMPERSONATION');
      assert.ok(fused.riskScore >= 70);

      // Verify deterministic technical evidence remains intact
      assert.ok(fused.evidence.some((e) => e.provenance === 'deterministic'));
      // Verify AI semantic evidence is explicitly present with AI provenance
      assert.ok(fused.evidence.some((e) => e.provenance === 'ai'));
      assert.strictEqual(fused.psychologicalTactics.length, 1);
      assert.ok(fused.interpretation.includes('انتحال صفة مصرفية'));
    });
  });

  // =========================================================================
  // B. Legitimate Security Warning (Must NOT turn into Scam)
  // =========================================================================
  describe('B. Legitimate Security Warning', () => {
    it('AI must not turn legitimate security advisory into a scam', () => {
      const text =
        'تنبيه أمني من مصرف الراجحي: لا تشارك رمز التحقق لمرة واحدة OTP أو كلمة المرور مع أي شخص. موظفونا لن يطلبوها منك أبداً.';
      const deterministic = analyzeDeterministic({ text });

      const mockAi: GeminiSemanticAnalysis = {
        interpretation:
          'هذه رسالة تحذيرية وتوعوية رسمية من المصرف لتنبيه العملاء بالحفاظ على سرية الرموز وليست طلباً احتيالياً.',
        scamTypeCandidates: [{ type: 'UNKNOWN', confidence: 0.1 }],
        semanticSignals: [],
        psychologicalTactics: [],
        scamDnaCandidates: [],
        aiConfidence: 0.95,
        uncertainties: ['رسالة توعوية لا تتضمن أي روابط أو مطالبات مالية'],
      };

      const fused = fuseEvidenceAndAssess(deterministic, mockAi);

      assert.strictEqual(fused.riskLevel, 'low');
      assert.ok(fused.riskScore <= 15, `Score expected <= 15, got ${fused.riskScore}`);
      assert.strictEqual(fused.detectedFeatures.includes('otp_request'), false);
      assert.strictEqual(fused.detectedFeatures.includes('credential_request'), false);
    });
  });

  // =========================================================================
  // C. Social Engineering Without Obvious Keywords
  // =========================================================================
  describe('C. Social Engineering Identification', () => {
    it('Gemini identifies semantic manipulation and authority bias where deterministic rules are weak', () => {
      const text =
        'أنا المدير الإقليمي وجالس في اجتماع مهم جداً الآن ومحتاج تحول دفعة المستخلص المستعجلة فوراً للمورد قبل نهاية الدوام، اعتمد الموضوع بدون تأخير.';
      const deterministic = analyzeDeterministic({ text });

      const mockAi: GeminiSemanticAnalysis = {
        interpretation:
          'محاولة هندسة اجتماعية كلاسيكية للاحتيال على الموظفين (Business Email Compromise / CEO Fraud) عبر ادعاء صفة المدير وممارسة ضغط زمني وسلطوي.',
        scamTypeCandidates: [{ type: 'SOCIAL_ENGINEERING', confidence: 0.9 }],
        semanticSignals: [
          {
            type: 'انتحال صفة إدارية عليا',
            description: 'ادعاء شخصية المدير لتعطيل الإجراءات الرقابية المعتادة',
            evidence: 'أنا المدير الإقليمي',
            severity: 'high',
          },
        ],
        psychologicalTactics: [
          {
            type: 'استغلال السلطة والتراتبية الوظيفية',
            description: 'إشعار المتلقي بالحرج من مراجعة أو تدقيق طلب صادر من رئيسه المباشر',
            evidence: 'أنا المدير الإقليمي وجالس في اجتماع مهم',
          },
          {
            type: 'الضغط الزمني الحرج',
            description: 'التذرع بانتهاء وقت الدوام لتجاوز التدقيق المالي',
            evidence: 'قبل نهاية الدوام، اعتمد الموضوع بدون تأخير',
          },
        ],
        scamDnaCandidates: [
          { feature: 'action_pressure', evidence: 'اعتمد الموضوع بدون تأخير', confidence: 0.85 },
          { feature: 'urgency', evidence: 'فوراً', confidence: 0.85 },
        ],
        aiConfidence: 0.88,
        uncertainties: ['الرسالة لا تحتوي على روابط صريحة ولكن السياق الإداري مشبوه للغاية'],
      };

      const fused = fuseEvidenceAndAssess(deterministic, mockAi);

      assert.strictEqual(fused.scamType, 'SOCIAL_ENGINEERING');
      assert.ok(fused.psychologicalTactics.length >= 2);
      assert.ok(fused.evidence.some((e) => e.provenance === 'ai'));
    });
  });

  // =========================================================================
  // D. Yemeni / Colloquial Arabic Dialect Understanding
  // =========================================================================
  describe('D. Yemeni Colloquial Arabic Scenario', () => {
    it('correctly interprets Yemeni dialect context and local payment terms', () => {
      const text =
        'يا غالي ضروري تتصل بي، حساب الكريمي حقك معلق ويشتي فك الحظر، ارسل لي رقم الحوالة والكود حق التأكيد سريع.';
      const deterministic = analyzeDeterministic({ text });

      const mockAi: GeminiSemanticAnalysis = {
        interpretation:
          'رسالة بلهجة يمنية دارجة تتضمن انتحالاً لخدمة بنك الكريمي وطلباً لفك الحظر عبر استدراج كود التأكيد ورقم الحوالة.',
        scamTypeCandidates: [{ type: 'BANK_IMPERSONATION', confidence: 0.9 }],
        semanticSignals: [
          {
            type: 'استدراج كود التأكيد بلهجة دارجة',
            description: 'طلب مباشر لكود التأكيد ورقم الحوالة بزعم فك حظر حساب الكريمي',
            evidence: 'الكود حق التأكيد سريع',
            severity: 'high',
          },
        ],
        psychologicalTactics: [
          {
            type: 'التودد المضلل والضغط العاجل',
            description: 'استخدام عبارات الألفة (يا غالي) المقترنة بالاستعجال',
            evidence: 'يا غالي ضروري تتصل بي',
          },
        ],
        scamDnaCandidates: [
          { feature: 'impersonation', evidence: 'الكريمي', confidence: 0.85 },
          { feature: 'otp_request', evidence: 'الكود حق التأكيد سريع', confidence: 0.9 },
          { feature: 'urgency', evidence: 'سريع', confidence: 0.8 },
        ],
        aiConfidence: 0.9,
        uncertainties: [],
      };

      const fused = fuseEvidenceAndAssess(deterministic, mockAi);

      assert.strictEqual(fused.scamType, 'BANK_IMPERSONATION');
      assert.ok(fused.interpretation.includes('الكريمي'));
      assert.ok(fused.detectedFeatures.includes('otp_request'));
    });
  });

  // =========================================================================
  // E. Arabic + English Mixed Language Scenario
  // =========================================================================
  describe('E. Mixed Arabic + English Scenario', () => {
    it('handles mixed English terminology (account, verify, OTP)', () => {
      const text =
        'عزيزي العميل، Your bank account has been suspended. Please verify your identity and send OTP code now.';
      const deterministic = analyzeDeterministic({ text });

      const mockAi: GeminiSemanticAnalysis = {
        interpretation:
          'رسالة هجينة تمزج العربية والإنجليزية تدعي تجميد الحساب وتطلب رمز الـ OTP بشكل صريح.',
        scamTypeCandidates: [{ type: 'BANK_IMPERSONATION', confidence: 0.92 }],
        semanticSignals: [
          {
            type: 'طلب صريح لرمز OTP بالإنجليزية',
            description: 'طلب إرسال رمز التحقق في سياق تعليق الحساب',
            evidence: 'send OTP code now',
            severity: 'high',
          },
        ],
        psychologicalTactics: [
          {
            type: 'التهديد بتعليق الحساب',
            description: 'استخدام مصطلح account suspended لإرباك الضحية',
            evidence: 'account has been suspended',
          },
        ],
        scamDnaCandidates: [
          { feature: 'otp_request', evidence: 'send OTP code now', confidence: 0.95 },
          { feature: 'threat_language', evidence: 'account has been suspended', confidence: 0.9 },
        ],
        aiConfidence: 0.95,
        uncertainties: [],
      };

      const fused = fuseEvidenceAndAssess(deterministic, mockAi);

      assert.strictEqual(fused.scamType, 'BANK_IMPERSONATION');
      assert.ok(fused.detectedFeatures.includes('otp_request'));
      assert.ok(fused.detectedFeatures.includes('threat_language'));
    });
  });

  // =========================================================================
  // F. Arabizi Transliteration Scenario
  // =========================================================================
  describe('F. Arabizi Transliteration Scenario', () => {
    it('correctly interprets Arabizi numbers and vocabulary', () => {
      const text = '7sabak tgfl ya 3aziz, ed5ol el rabit fawran w 7ot el password.';
      const deterministic = analyzeDeterministic({ text });

      const mockAi: GeminiSemanticAnalysis = {
        interpretation:
          'رسالة مكتوبة بأحرف العربيزي (Arabizi) تزعم قفل الحساب وتطلب الدخول الفوري ووضع كلمة المرور.',
        scamTypeCandidates: [{ type: 'BANK_IMPERSONATION', confidence: 0.88 }],
        semanticSignals: [
          {
            type: 'طلب كلمة المرور بالعربيزي',
            description: 'استدراج صريح لكلمة المرور بصيغة عربيزي',
            evidence: '7ot el password',
            severity: 'high',
          },
        ],
        psychologicalTactics: [],
        scamDnaCandidates: [
          { feature: 'credential_request', evidence: '7ot el password', confidence: 0.9 },
          { feature: 'urgency', evidence: 'fawran', confidence: 0.85 },
        ],
        aiConfidence: 0.9,
        uncertainties: ['النص مدخل بأبجدية العربيزي غير الرسمية'],
      };

      const fused = fuseEvidenceAndAssess(deterministic, mockAi);

      assert.ok(fused.detectedFeatures.includes('credential_request'));
      assert.ok(fused.interpretation.includes('العربيزي'));
    });
  });

  // =========================================================================
  // H. Gemini Unavailable / Graceful Fallback
  // =========================================================================
  describe('H. Fallback Behavior when Gemini is Unavailable', () => {
    it('should successfully complete deterministic analysis when Gemini is unconfigured', async () => {
      const text =
        'مبروك! ربحت معنا سيارة بقيمة 100000 ريال، اضغط الرابط فوراً لاستلام جائزتك: http://claim-prize.top/win';

      // Explicitly pass client: null to simulate missing API key or offline execution
      const res = await analyzeWithSemanticIntelligence({ text }, { client: null });

      assert.strictEqual(res.aiAvailable, false);
      assert.ok(res.aiFallbackReason);
      assert.strictEqual(res.aiConfidence, null);
      assert.strictEqual(res.scamType, 'FAKE_PRIZE');
      assert.strictEqual(res.riskLevel, 'high');
      assert.ok(res.riskScore >= 70);
      assert.ok(res.evidence.length > 0);
      assert.ok(res.evidence.every((e) => e.provenance === 'deterministic'));
    });

    it('should fall back gracefully on API network/timeout error', async () => {
      // Mock client that throws network timeout
      const failingClient = {
        models: {
          generateContent: async () => {
            throw new Error('Connection timed out after 12000ms');
          },
        },
      };

      const execution = await analyzeSemantics(
        {
          originalText: 'رسالة اختبارية',
          normalizedText: 'رسالة اختبارية',
          extractedUrls: [],
          deterministicSignals: [],
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: failingClient as any }
      );

      assert.strictEqual(execution.success, false);
      assert.ok(execution.fallbackReason && execution.fallbackReason.includes('timed out'));
    });
  });

  // =========================================================================
  // I. AI Confidence Separation from Risk Score
  // =========================================================================
  describe('I. AI Confidence ≠ Risk Score Strict Separation', () => {
    it('aiConfidence of 0.99 must NOT become riskScore 99 on a benign message', () => {
      const text = 'السلام عليكم ورحمة الله، كيف حالك أخي الكريم؟';
      const deterministic = analyzeDeterministic({ text });

      // Model is 99% confident that this message is benign greeting
      const mockAi: GeminiSemanticAnalysis = {
        interpretation: 'رسالة تحية اجتماعية اعتيادية خالية من أي استدراج أو ضغط.',
        scamTypeCandidates: [{ type: 'UNKNOWN', confidence: 0.05 }],
        semanticSignals: [],
        psychologicalTactics: [],
        scamDnaCandidates: [],
        aiConfidence: 0.99, // 99% semantic interpretation confidence
        uncertainties: [],
      };

      const fused = fuseEvidenceAndAssess(deterministic, mockAi);

      assert.strictEqual(fused.aiConfidence, 0.99);
      // Risk score must NOT be 99! It must remain low!
      assert.strictEqual(fused.riskScore, 0);
      assert.strictEqual(fused.riskLevel, 'low');
    });
  });

  // =========================================================================
  // J. Evidence Provenance Transparency
  // =========================================================================
  describe('J. Evidence Provenance Transparency', () => {
    it('preserves clean distinction between deterministic and AI evidence', () => {
      const text =
        'يرجى سداد رسوم التوصيل 10 ريال عبر https://spl-track.top لتجنب إعادة الشحنة.';
      const deterministic = analyzeDeterministic({ text });

      const mockAi: GeminiSemanticAnalysis = {
        interpretation: 'احتيال طرود بريدية يستغل حاجة المتلقي لاستلام شحنته.',
        scamTypeCandidates: [{ type: 'DELIVERY_SCAM', confidence: 0.9 }],
        semanticSignals: [
          {
            type: 'استغلال ترقب الشحنة',
            description: 'إيهام المتلقي بوجود شحنة معلقة لدفع رسوم وهمية',
            evidence: 'لتجنب إعادة الشحنة',
            severity: 'high',
          },
        ],
        psychologicalTactics: [
          {
            type: 'الخوف من فقدان الطرد',
            description: 'التهديد بإعادة الطرد لإجبار الضحية على السداد السريع',
            evidence: 'لتجنب إعادة الشحنة',
          },
        ],
        scamDnaCandidates: [
          { feature: 'suspicious_payment_request', evidence: 'سداد رسوم التوصيل', confidence: 0.9 },
          { feature: 'urgency', evidence: 'لتجنب إعادة الشحنة', confidence: 0.8 },
        ],
        aiConfidence: 0.9,
        uncertainties: [],
      };

      const fused = fuseEvidenceAndAssess(deterministic, mockAi);

      // Verify deterministic items have provenance: 'deterministic'
      const deterministicItems = fused.evidence.filter((e) => e.provenance === 'deterministic');
      assert.ok(deterministicItems.length > 0);

      // Verify AI items have provenance: 'ai'
      const aiItems = fused.evidence.filter((e) => e.provenance === 'ai');
      assert.ok(aiItems.length > 0);

      // Verify DNA provenance tracking
      const paymentDna = fused.scamDna.find((d) => d.featureId === 'suspicious_payment_request');
      assert.ok(paymentDna);
      assert.strictEqual(paymentDna.provenance, 'both'); // both deterministic rule and AI identified it
    });
  });

  // =========================================================================
  // Requirement 4: Centralized AI Score Cap Regression Tests
  // =========================================================================
  describe('Centralized AI Score Cap Regression Tests (Requirement 4)', () => {
    it('strictly clamps raw AI contribution when exceeding the 15-point heuristic cap', () => {
      // Clean social message with zero deterministic signals (deterministic score = 0)
      const text = 'السلام عليكم ورحمة الله، كيف حالك أخي الكريم؟ طمني عن صحتك وأحوال الأهل.';
      const deterministic = analyzeDeterministic({ text });

      assert.strictEqual(deterministic.assessment.score, 0);
      assert.strictEqual(deterministic.assessment.level, 'low');
      assert.strictEqual(deterministic.detectedFeatures.length, 0);

      // Construct a mock AI response with 5 independent Scam DNA features + tactics
      // In fusion.ts: each DNA candidate with confidence 1.0 contributes Math.round(5 * 1.0) = 5 points
      // 5 features * 5 points = 25 raw contribution points + 2 points for tactics = 27 raw contribution points!
      const mockAiWithAbundantEvidence: GeminiSemanticAnalysis = {
        interpretation: 'رسالة تم تفسيرها بنوايا متعددة.',
        scamTypeCandidates: [{ type: 'SOCIAL_ENGINEERING', confidence: 0.85 }],
        semanticSignals: [
          { type: 'ضغط زمني', description: 'وصف', evidence: 'طمني', severity: 'medium' },
          { type: 'تودد اجتماعي', description: 'وصف', evidence: 'أخي الكريم', severity: 'low' },
        ],
        psychologicalTactics: [
          { type: 'تلاعب عاطفي', description: 'وصف', evidence: 'طمني عن صحتك' },
        ],
        scamDnaCandidates: [
          { feature: 'urgency', evidence: 'طمني', confidence: 1.0 },
          { feature: 'secrecy_pressure', evidence: 'أخي الكريم', confidence: 1.0 },
          { feature: 'action_pressure', evidence: 'طمني', confidence: 1.0 },
          { feature: 'financial_lure', evidence: 'أحوال', confidence: 1.0 },
          { feature: 'unexpected_contact', evidence: 'السلام عليكم', confidence: 1.0 },
        ],
        aiConfidence: 0.9,
        uncertainties: [],
      };

      // Calculate raw AI contribution before cap:
      let calculatedRawAiContribution = 0;
      for (const cand of mockAiWithAbundantEvidence.scamDnaCandidates) {
        calculatedRawAiContribution += Math.round(5 * cand.confidence);
      }
      calculatedRawAiContribution += Math.min(5, mockAiWithAbundantEvidence.psychologicalTactics.length * 2);

      // Verify raw AI contribution is genuinely greater than 15
      assert.ok(
        calculatedRawAiContribution > 15,
        `Expected raw AI contribution > 15, got ${calculatedRawAiContribution}`
      );
      assert.strictEqual(calculatedRawAiContribution, 27);

      // Execute fusion with default weights
      const fused = fuseEvidenceAndAssess(deterministic, mockAiWithAbundantEvidence);

      // Verify final AI contribution is strictly capped at DEFAULT_RISK_WEIGHTS.maxAiScoreContribution (15)
      const finalAiContribution = fused.riskScore - deterministic.assessment.score;
      assert.ok(
        finalAiContribution <= DEFAULT_RISK_WEIGHTS.maxAiScoreContribution,
        `Expected final AI contribution <= ${DEFAULT_RISK_WEIGHTS.maxAiScoreContribution}, got ${finalAiContribution}`
      );
      assert.strictEqual(finalAiContribution, 15);
      assert.strictEqual(fused.riskScore, 15);

      // Verify that AI alone CANNOT push a clean deterministic result into 'suspicious' (>= 30) or 'high' (>= 70)
      assert.strictEqual(fused.riskLevel, 'low');
      assert.ok(fused.riskScore <= DEFAULT_RISK_WEIGHTS.thresholds.lowMax);

      // Verify deterministic evidence remains intact (0 deterministic signals)
      assert.strictEqual(fused.deterministicResult.assessment.score, 0);

      // Verify provenance is accurately set to 'ai' for AI-derived DNA features
      const urgencyDna = fused.scamDna.find((d) => d.featureId === 'urgency');
      assert.ok(urgencyDna);
      assert.strictEqual(urgencyDna.provenance, 'ai');
      assert.strictEqual(urgencyDna.detected, true);
    });
  });
});
