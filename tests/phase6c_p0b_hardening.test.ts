import { describe, it } from 'node:test';
import assert from 'node:assert';
import { analyzeUnified } from '../lib/vision/pipeline';
import { analyzeDeterministic } from '../lib/analysis';

describe('Phase 6C — P0-B: Multiple URLs + No-URL Scam Detection', () => {
  // =========================================================================
  // Target 1: Multiple URLs & Decoy URLs
  // =========================================================================
  describe('Target 1 — Multiple URLs & Decoy Resilience', () => {
    it('RED-034: Detects banking phishing URL even when paired with official bank link', async () => {
      const input = {
        text: 'عزيزي العميل، حرصاً على أمانك يمكنك مراجعة شروط الخدمة عبر موقعنا الرسمي https://alrajhibank.com.sa ولكن لتحديث بياناتك البنكية الآن افتح: https://alrajhi-update.top/auth',
        url: 'https://alrajhi-update.top/auth',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'high');
      assert.strictEqual(result.scamType, 'BANK_IMPERSONATION');
      assert.ok(result.detectedFeatures.includes('credential_request'));
      assert.ok(result.detectedFeatures.includes('impersonation'));

      // Check urlFindings
      const det = analyzeDeterministic(input);
      assert.ok(det.assessment.urlFindings);
      assert.strictEqual(det.assessment.urlFindings!.totalUrls, 2);
      assert.strictEqual(det.assessment.urlFindings!.suspiciousUrlsCount, 1);

      const official = det.assessment.urlFindings!.urls.find((u) => u.hostname.includes('alrajhibank.com.sa'));
      const fake = det.assessment.urlFindings!.urls.find((u) => u.hostname.includes('alrajhi-update.top'));

      assert.ok(official);
      assert.strictEqual(official!.isSuspicious, false);
      assert.ok(fake);
      assert.strictEqual(fake!.isSuspicious, true);
      assert.ok(fake!.anomalies.includes('رابط مشبوه مقترن برابط رسمي/موثوق (تمويه بروابط متعددة)'));
    });

    it('RED-035: Detects fake prize scam even when paired with official Twitter link', async () => {
      const input = {
        text: 'تابع تغريداتنا الرسمية على تويتر https://twitter.com/stc_ksa ولتفعيل باقة الإنترنت المجانية 100 جيجا ادخل رقم هاتفك هنا: https://stc-gift.click/claim',
        url: 'https://stc-gift.click/claim',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'high');
      assert.strictEqual(result.scamType, 'FAKE_PRIZE');
      assert.ok(result.detectedFeatures.includes('financial_lure'));
      assert.ok(result.detectedFeatures.includes('impersonation'));
    });

    it('RED-036: Multiple legitimate URLs remain strictly LOW risk', async () => {
      const input = {
        text: 'للاطلاع على التوثيق الفني للمشروع راجع https://github.com/facebook/react وللحصول على أمثلة الكود تفضل بزيارة https://react.dev في أي وقت.',
        url: 'https://react.dev',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'low');
      assert.strictEqual(result.scamType, 'UNKNOWN');
      assert.ok(result.riskScore < 30);

      const det = analyzeDeterministic(input);
      assert.strictEqual(det.assessment.urlFindings!.totalUrls, 2);
      assert.strictEqual(det.assessment.urlFindings!.suspiciousUrlsCount, 0);
    });
  });

  // =========================================================================
  // Target 2: Scams Without URL
  // =========================================================================
  describe('Target 2 — Social-Engineering Scams Without URL', () => {
    it('RED-040: Detects Yemeni prize scam directing to phone and teller (no URL)', async () => {
      const input = {
        text: 'مبروك فزت معنا بجائزة نقدية 2 مليون ريال يمني في سحب مهرجان الصيف. لاستلام المبلغ توجه لأقرب صراف كريمي وتواصل مع الأستاذ محمد عبر الاتصال بالرقم [PHONE] لتسليم كود الحوالة.',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'high');
      assert.strictEqual(result.scamType, 'FAKE_PRIZE');
      assert.ok(result.detectedFeatures.includes('financial_lure'));
      assert.ok(result.detectedFeatures.includes('action_pressure'));
    });

    it('RED-041: Detects Gulf Mada suspension directing to WhatsApp (no URL)', async () => {
      const input = {
        text: 'عزيزي العميل، تم إيقاف بطاقة مدى البنكية الخاصة بك لتفادي سرقة رصيدك. يرجى إرسال رسالة واتساب عاجلة إلى مسؤول الحسابات عبر الرقم [PHONE] لإعادة التفعيل.',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'high');
      assert.strictEqual(result.scamType, 'BANK_IMPERSONATION');
      assert.ok(result.detectedFeatures.includes('impersonation'));
      assert.ok(result.detectedFeatures.includes('threat_language'));
      assert.ok(result.detectedFeatures.includes('action_pressure'));
    });

    it('RED-042: Detects Egyptian Central Bank fake grant directing to phone (no URL)', async () => {
      const input = {
        text: 'يا فندم مبروك كسبت معانا منحة مالية 50 ألف جنيه من البنك المركزي. اتصل حالاً على [PHONE] عشان نمليك بيانات استلام الشيك البنكي قبل انتهاء الدوام.',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'high');
      assert.strictEqual(result.scamType, 'FAKE_PRIZE');
      assert.ok(result.detectedFeatures.includes('financial_lure'));
      assert.ok(result.detectedFeatures.includes('impersonation'));
      assert.ok(result.detectedFeatures.includes('action_pressure'));
    });

    it('RED-038: Detects fake government fine extortion and classifies correctly', async () => {
      const input = {
        text: 'سعادة المحترم: تهديكم الهيئة العامة أطيب التحيات. نفيدكم بوجود غرامة قضائية مستحقة ويجب تحويل 500 ريال فوراً لحساب مجهول لتجنب صدور أمر قبض: https://court-fine.click',
        url: 'https://court-fine.click',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'high');
      assert.strictEqual(result.scamType, 'GOVERNMENT_IMPERSONATION');
      assert.ok(result.detectedFeatures.includes('impersonation'));
      assert.ok(result.detectedFeatures.includes('threat_language'));
      assert.ok(result.detectedFeatures.includes('suspicious_payment_request'));
    });

    it('RED-039: Detects WhatsApp takeover via OTP request', async () => {
      const input = {
        text: 'حياك يا ابن العم وجمعة مباركة عليك وعلى الأهل. بالله عليك خش هذا الرابط وسوي تأكيد لرمز التحقق اللي بيوصلك عشان أسترجع حسابي: https://whatsapp-auth.xyz',
        url: 'https://whatsapp-auth.xyz',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'high');
      assert.strictEqual(result.scamType, 'ACCOUNT_TAKEOVER');
      assert.ok(result.detectedFeatures.includes('otp_request'));
      assert.ok(result.detectedFeatures.includes('impersonation'));
    });
  });

  // =========================================================================
  // Hard Negatives & Regression Protection
  // =========================================================================
  describe('Hard Negatives & Regression Protection', () => {
    it('LEGIT-001: Bank negative OTP warning remains strictly LOW risk', async () => {
      const input = {
        text: 'تنبيه أمني من مصرف الراجحي: نؤكد لعملائنا الكرام أن المصرف لن يطلب منك إطلاقاً الإفصاح عن رمز التحقق (OTP) أو الرقم السري للبطاقة. حافظ على سرية بياناتك وتجاهل أي اتصالات مجهولة.',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'low');
      assert.ok(!result.detectedFeatures.includes('otp_request'));
      assert.ok(!result.detectedFeatures.includes('impersonation'));
    });

    it('LEGIT-002: Routine POS card transaction notice remains strictly LOW risk', async () => {
      const input = {
        text: 'تمت عملية شراء عبر نقاط البيع بواسطة بطاقتك مدى المنتهية بـ [CARD_LAST4] بمبلغ 85.50 ريال لدى أسواق التميمي. رصيدك المتاح الحالي هو 4,210.25 ريال.',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'low');
      assert.strictEqual(result.scamType, 'UNKNOWN');
      assert.strictEqual(result.detectedFeatures.length, 0);
    });

    it('LEGIT-003: Kuraimi salary deposit notice remains strictly LOW risk', async () => {
      const input = {
        text: 'عزيزي العميل، تم قيد مبلغ 120,000 ريال يمني في حسابك الجاري لدى بنك الكريمي حوالة راتب شهر أغسطس. شكراً لاستخدامك خدماتنا.',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'low');
      assert.strictEqual(result.scamType, 'UNKNOWN');
      assert.ok(!result.detectedFeatures.includes('impersonation'));
      assert.ok(!result.detectedFeatures.includes('financial_lure'));
    });

    it('LEGIT-009: Routine utility payment receipt remains strictly LOW risk', async () => {
      const input = {
        text: 'عزيزي المشترك، نشكركم على سداد فاتورة الكهرباء للحساب [ACCOUNT_ID] بقيمة 320.00 ريال. تم قيد المبلغ بنجاح ورقم السداد المرجعي هو [REF_ID].',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'low');
      assert.ok(!result.detectedFeatures.includes('suspicious_payment_request'));
    });

    it('ADV-005: Bilingual legitimate B2B invoice request remains strictly LOW risk', async () => {
      const input = {
        text: 'Dear Partner, kindly review invoice #INV-[INVOICE_ID] regarding monthly cloud hosting payment before tomorrow 5 PM. يرجى إشعارنا فور التحويل البنكي للاعتماد.',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'low');
      assert.ok(!result.detectedFeatures.includes('suspicious_payment_request'));
    });

    it('ADV-003: Strict negative OTP banking warning remains strictly LOW risk', async () => {
      const input = {
        text: 'تحذير أمني صارم: موظف البنك لن يطلب منك قط كلمة السر أو رمز التحقق لمرة واحدة OTP، وإذا طلب منك أي شخص هذا الرمز فهو محتال ويجب إبلاغنا فوراً.',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'low');
      assert.ok(!result.detectedFeatures.includes('otp_request'));
    });

    it('LEGIT-011: Legitimate government OTP issuance without link remains LOW risk', async () => {
      const input = {
        text: 'رمز التحقق الخاص بك لمنصة الخدمات الإلكترونية هو: [OTP]. صالح لمدة 5 دقائق. لا تشارك هذا الرمز مع أي شخص.',
      };

      const result = await analyzeUnified(input);

      assert.strictEqual(result.riskLevel, 'low');
      assert.ok(!result.detectedFeatures.includes('otp_request'));
    });
  });

  // =========================================================================
  // Evidence Grounding & Provenance
  // =========================================================================
  describe('Evidence Grounding & Provenance', () => {
    it('Ensures all evidence quotes are strictly contained in source input', async () => {
      const cases = [
        {
          text: 'عزيزي العميل، حرصاً على أمانك يمكنك مراجعة شروط الخدمة عبر موقعنا الرسمي https://alrajhibank.com.sa ولكن لتحديث بياناتك البنكية الآن افتح: https://alrajhi-update.top/auth',
          url: 'https://alrajhi-update.top/auth',
        },
        {
          text: 'يا فندم مبروك كسبت معانا منحة مالية 50 ألف جنيه من البنك المركزي. اتصل حالاً على [PHONE] عشان نمليك بيانات استلام الشيك البنكي قبل انتهاء الدوام.',
        },
        {
          text: 'مبروك فزت معنا بجائزة نقدية 2 مليون ريال يمني في سحب مهرجان الصيف. لاستلام المبلغ توجه لأقرب صراف كريمي وتواصل مع الأستاذ محمد عبر الاتصال بالرقم [PHONE] لتسليم كود الحوالة.',
        },
      ];

      for (const c of cases) {
        const result = await analyzeUnified(c);
        const combined = `${c.text || ''} ${c.url || ''}`.toLowerCase();

        for (const ind of result.scamDna) {
          for (const ev of ind.evidence) {
            if (ev && ev.length > 3) {
              const cleanEv = ev.toLowerCase().replace(/[\u200B-\u200D\uFEFF\u00A0]/g, ' ').trim();
              assert.ok(
                combined.includes(cleanEv),
                `Evidence quote "${ev}" must be contained in "${combined}"`
              );
            }
          }
        }
      }
    });
  });
});
