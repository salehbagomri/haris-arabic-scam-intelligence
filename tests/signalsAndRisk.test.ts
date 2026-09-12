import { describe, it } from 'node:test';
import assert from 'node:assert';
import { analyzeDeterministic } from '../lib/analysis';

describe('Deterministic Signals & Risk Engine Tests', () => {
  describe('Scam Cases (High Suspicion)', () => {
    it('Case 1: Arabic Banking Impersonation Scam', () => {
      const text =
        'عزيزي العميل، تم إيقاف بطاقتك الائتمانية مؤقتاً لأسباب أمنية. يرجى تحديث بياناتك فوراً خلال ساعتين لتجنب الغرامة عبر الرابط: https://alrajhi-secure-login.xyz/verify وإدخال رمز التحقق.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(res.assessment.level, 'high');
      assert.ok(res.assessment.score >= 70, `Score expected >= 70, got ${res.assessment.score}`);
      assert.strictEqual(res.assessment.scamType, 'BANK_IMPERSONATION');
      assert.ok(res.detectedFeatures.includes('urgency'));
      assert.ok(res.detectedFeatures.includes('threat_language'));
      assert.ok(res.detectedFeatures.includes('suspicious_url'));
      assert.ok(res.detectedFeatures.includes('otp_request'));
      assert.ok(res.assessment.evidence.length >= 3);
      assert.ok(res.assessment.actionableAdvice.length > 0);
    });

    it('Case 2: Fake Prize / Lottery Scam', () => {
      const text =
        'مبروك! ربحت معنا سيارة بقيمة 100000 ريال، اضغط الرابط فوراً لاستلام جائزتك: http://claim-prize.top/win';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(res.assessment.level, 'high');
      assert.strictEqual(res.assessment.scamType, 'FAKE_PRIZE');
      assert.ok(res.detectedFeatures.includes('financial_lure'));
      assert.ok(res.detectedFeatures.includes('action_pressure'));
      assert.ok(res.detectedFeatures.includes('suspicious_url'));
    });

    it('Case 3: Courier & Delivery Fee Scam', () => {
      const text =
        'شحنتك رقم SA-9921 معلقة في المستودع، يرجى سداد رسوم التوصيل المعلقة 9.50 ريال لاستلام الطرد عبر: https://spl-saudi-track.live/pay';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(res.assessment.level, 'high');
      assert.strictEqual(res.assessment.scamType, 'DELIVERY_SCAM');
      assert.ok(res.detectedFeatures.includes('suspicious_payment_request'));
      assert.ok(res.detectedFeatures.includes('suspicious_url'));
    });

    it('Case 4: Direct OTP Harvesting Scam', () => {
      const text = 'أدخل رمز التحقق المؤقت otp المرسل لهاتفك حالياً لتفعيل الحساب قبل فوات الأوان.';
      const res = analyzeDeterministic({ text });

      assert.ok(res.detectedFeatures.includes('otp_request'));
      assert.ok(res.detectedFeatures.includes('urgency'));
      assert.ok(res.assessment.score >= 35);
      assert.ok(['high', 'suspicious'].includes(res.assessment.level));
    });

    it('Case 5: Investment Ponzi Scam', () => {
      const text =
        'فرصة استثمار مضمون وأرباح يومية مؤكدة 100% بدون أي خسارة، سارع بالتسجيل الآن وخلّ الموضوع سري بيننا فقط.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(res.assessment.scamType, 'INVESTMENT_SCAM');
      assert.ok(res.detectedFeatures.includes('financial_lure'));
      assert.ok(res.detectedFeatures.includes('secrecy_pressure'));
      assert.ok(res.detectedFeatures.includes('action_pressure'));
    });

    it('Case 6: Obfuscated Dialectal Scam with Arabizi', () => {
      const text = '7sabak تم ايقافه يا غالي 🎉 كسبت معنا قسيمه بـ 3000 ريال، اضغط الرابط http://stc-rewards.top';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(res.assessment.level, 'high');
      assert.ok(res.detectedFeatures.includes('financial_lure'));
      assert.ok(res.detectedFeatures.includes('suspicious_url'));
      assert.strictEqual(res.normalizedText?.hasArabizi, true);
    });
  });

  describe('Hard Negatives & Legitimate Messages (Low Suspicion)', () => {
    it('Hard Negative 1: Legitimate Security Warning (Must NOT detect OTP request)', () => {
      const text =
        'تنبيه أمني من مصرف الراجحي: للحفاظ على أمان حسابك، لا تشارك رمز التحقق مع أي شخص، موظفونا لن يطلبوا منك كلمة المرور إطلاقاً.';
      const res = analyzeDeterministic({ text });

      // Crucial test: Intent-aware negation must prevent firing otp_request or credential_request
      assert.strictEqual(res.detectedFeatures.includes('otp_request'), false);
      assert.strictEqual(res.detectedFeatures.includes('credential_request'), false);
      assert.strictEqual(res.assessment.level, 'low');
      assert.ok(res.assessment.score <= 25, `Expected score <= 25, got ${res.assessment.score}`);
    });

    it('Hard Negative 2: Legitimate Delivery Status Notification', () => {
      const text =
        'عزيزي العميل، تم شحن طلبك رقم 44820 بنجاح وهو الآن في طريقه إليك عبر شركة سمسا. شكراً لتسوقك معنا.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(res.assessment.level, 'low');
      assert.strictEqual(res.detectedFeatures.includes('suspicious_payment_request'), false);
      assert.ok(res.assessment.score <= 15);
    });

    it('Hard Negative 3: Legitimate Store Marketing Offer', () => {
      const text =
        'عروض نهاية الأسبوع في متجرنا: خصم 20% على تشكيلة الملابس الشتوية في جميع الفروع. نتشرف بزيارتكم.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(res.assessment.level, 'low');
      assert.strictEqual(res.detectedFeatures.includes('suspicious_url'), false);
      assert.strictEqual(res.detectedFeatures.includes('threat_language'), false);
      assert.strictEqual(res.assessment.score, 0);
    });

    it('Hard Negative 4: Ordinary Arabic Social Conversation', () => {
      const text =
        'السلام عليكم يا أخي الكريم، كيف حالك وحال الأهل؟ إن شاء الله نلتقي غداً في المسجد بعد صلاة العصر.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(res.assessment.score, 0);
      assert.strictEqual(res.assessment.level, 'low');
      assert.strictEqual(res.detectedFeatures.length, 0);
    });
  });
});
