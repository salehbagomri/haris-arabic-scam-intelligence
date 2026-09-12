import { describe, it } from 'node:test';
import assert from 'node:assert';
import { analyzeDeterministic } from '../lib/analysis';
import { extractUrlsFromText } from '../lib/analysis/normalizer';
import { analyzeUrl } from '../lib/analysis/urlAnalyzer';

describe('HARIS Phase 3.1: Precision Hardening Regression Tests', () => {
  // =========================================================================
  // 1. BRAND MENTION ≠ IMPERSONATION
  // =========================================================================
  describe('1. Brand Mention False Positives', () => {
    it('Case 1: "اقرأ خبر توسع الراجحي" must NOT trigger impersonation', () => {
      const text = 'اقرأ خبر توسع الراجحي في قطاع تمويل المنشآت الصغيرة والمتوسطة اليوم.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(
        res.detectedFeatures.includes('impersonation'),
        false,
        'Brand mention alone must not produce an impersonation signal'
      );
      assert.strictEqual(res.assessment.level, 'low');
    });

    it('Case 2: "أعلن مصرف الراجحي عن خدمة جديدة" must NOT trigger impersonation', () => {
      const text = 'أعلن مصرف الراجحي عن خدمة جديدة للتحويلات الدولية عبر تطبيقه المحدث.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(
        res.detectedFeatures.includes('impersonation'),
        false,
        'Brand mention in legitimate news/announcement must not trigger impersonation'
      );
      assert.strictEqual(res.assessment.level, 'low');
    });

    it('Case 2b: "هذا مقال عن البنك الأهلي" must NOT trigger impersonation', () => {
      const text = 'هذا مقال عن البنك الأهلي وتاريخ تأسيسه في المملكة العربية السعودية.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(
        res.detectedFeatures.includes('impersonation'),
        false,
        'Entity mention in general prose must not trigger impersonation'
      );
      assert.strictEqual(res.assessment.level, 'low');
    });

    it('Case 3: "نحن من مصرف الراجحي ونحتاج تحديث بياناتك" CAN trigger impersonation', () => {
      const text = 'نحن من مصرف الراجحي ونحتاج تحديث بياناتك المصرفية فوراً.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(
        res.detectedFeatures.includes('impersonation'),
        true,
        'Explicit identity claim ("نحن من...") MUST produce an impersonation signal'
      );
    });

    it('Case 3b: "تم إيقاف حسابك لدى الراجحي، اضغط هنا للتفعيل" triggers impersonation & threat', () => {
      const text = 'تم إيقاف حسابك لدى الراجحي، اضغط هنا للتفعيل فوراً.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(res.detectedFeatures.includes('impersonation'), true);
      assert.strictEqual(res.detectedFeatures.includes('threat_language'), true);
    });
  });

  // =========================================================================
  // 2. BRAND IN URL PATH ≠ DOMAIN IMPERSONATION
  // =========================================================================
  describe('2. Brand in URL Path False Positives', () => {
    it('Case 4: https://general-news-portal.com/article/alrajhi-expansion must NOT produce domain impersonation', () => {
      const url = 'https://general-news-portal.com/article/alrajhi-expansion';
      const urlRes = analyzeUrl(url);

      assert.strictEqual(urlRes.isValid, true);
      assert.strictEqual(
        urlRes.brandSpoofing.detected,
        false,
        'Brand keyword in path must NOT be flagged as spoofing'
      );
      assert.strictEqual(urlRes.brandSpoofing.location, 'path');
      assert.strictEqual(
        urlRes.signals.some((s) => s.featureId === 'impersonation'),
        false,
        'No impersonation signal should be generated for brand in path'
      );

      const overall = analyzeDeterministic({ url });
      assert.strictEqual(overall.detectedFeatures.includes('impersonation'), false);
    });

    it('Case 5: https://alrajhi.secure-login.xyz/verify MUST produce impersonation evidence', () => {
      const url = 'https://alrajhi.secure-login.xyz/verify';
      const urlRes = analyzeUrl(url);

      assert.strictEqual(urlRes.isValid, true);
      assert.strictEqual(urlRes.brandSpoofing.detected, true);
      assert.strictEqual(urlRes.brandSpoofing.location, 'subdomain');
      assert.strictEqual(
        urlRes.signals.some((s) => s.featureId === 'impersonation'),
        true,
        'Brand in subdomain of unauthorized domain MUST trigger impersonation signal'
      );

      const overall = analyzeDeterministic({ url });
      assert.strictEqual(overall.detectedFeatures.includes('impersonation'), true);
      assert.strictEqual(overall.assessment.scamType, 'BANK_IMPERSONATION');
    });
  });

  // =========================================================================
  // 3. HARD NEGATIVES MUST BE LOCAL / CONTEXTUAL
  // =========================================================================
  describe('3. Clause-Level Local Negation for OTP', () => {
    it('Case 6: "لا تشارك رمز التحقق مع أي شخص" must NOT detect OTP request', () => {
      const text = 'تنبيه أمني: لا تشارك رمز التحقق مع أي شخص للحفاظ على سرية بياناتك.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(
        res.detectedFeatures.includes('otp_request'),
        false,
        'Legitimate security advisory must not be treated as an OTP request'
      );
    });

    it('Case 7: "موظفونا لن يطلبوا منك رمز التحقق" must NOT detect OTP request', () => {
      const text = 'عميلنا العزيز: موظفونا لن يطلبوا منك رمز التحقق لمرة واحدة OTP أو كلمة المرور أبداً.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(
        res.detectedFeatures.includes('otp_request'),
        false,
        'Negative disclaimer by institution must not trigger OTP request'
      );
    });

    it('Case 8: "لا تشارك الرمز مع أحد، لكن أرسله لي فورًا" MUST detect OTP request', () => {
      const text = 'لا تشارك الرمز مع أحد، لكن أرسله لي فورًا لتأكيد العملية.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(
        res.detectedFeatures.includes('otp_request'),
        true,
        'Negation in clause 1 must NOT suppress malicious request in clause 2'
      );
    });

    it('Case 9: "أرسل لي رمز التحقق الآن" MUST detect OTP request', () => {
      const text = 'يرجى تزويدي بالرمز أو أرسل لي رمز التحقق الآن.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(
        res.detectedFeatures.includes('otp_request'),
        true,
        'Direct imperative OTP request must be detected'
      );
    });
  });

  // =========================================================================
  // 4. TIGHTEN CREDENTIAL REQUEST DETECTION
  // =========================================================================
  describe('4. Credential Request Precision', () => {
    it('Case 10: "يمكنك تحديث حسابك من التطبيق" must NOT trigger credential request', () => {
      const text = 'يمكنك تحديث حسابك من التطبيق الرسمي في أي وقت ترغب به.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(
        res.detectedFeatures.includes('credential_request'),
        false,
        'Generic service language ("تحديث حسابك") without sensitive credentials must not trigger credential_request'
      );
    });

    it('Case 11: "تحديث بياناتك عبر الرابط وإدخال كلمة المرور" MUST trigger credential request', () => {
      const text = 'يرجى تحديث بياناتك عبر الرابط وإدخال كلمة المرور لتجنب إيقاف الخدمة.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(
        res.detectedFeatures.includes('credential_request'),
        true,
        'Explicit solicitation of password/credentials must trigger credential_request'
      );
    });

    it('Case 11b: Asking for card number or CVV triggers credential request', () => {
      const text = 'يرجى إدخال رقم البطاقة ورمز CVV لتأكيد هويتك.';
      const res = analyzeDeterministic({ text });

      assert.strictEqual(res.detectedFeatures.includes('credential_request'), true);
    });
  });

  // =========================================================================
  // 5. SUPPORT BARE DOMAINS
  // =========================================================================
  describe('5. Bare Domain Extraction Precision', () => {
    it('Case 12: Bare domains (example.com, alrajhibank.com.sa, secure-login.xyz) extracted accurately', () => {
      const text =
        'يرجى زيارة example.com وموقع alrajhibank.com.sa وموقع التصيد secure-login.xyz لفحص الروابط.';
      const extracted = extractUrlsFromText(text);

      assert.ok(extracted.includes('example.com'), 'Should extract bare domain example.com');
      assert.ok(extracted.includes('alrajhibank.com.sa'), 'Should extract bare domain alrajhibank.com.sa');
      assert.ok(extracted.includes('secure-login.xyz'), 'Should extract bare domain secure-login.xyz');
    });

    it('Case 13: Decimals and normal words resembling domain fragments must NOT be extracted', () => {
      const text = 'نسبة الفائدة هي 3.14%، وراجع الدليل e.g. المرفق في ملف report.pdf والنسخة v1.2.';
      const extracted = extractUrlsFromText(text);

      assert.strictEqual(
        extracted.includes('3.14'),
        false,
        'Decimals like 3.14 must not be extracted as domains'
      );
      assert.strictEqual(
        extracted.includes('e.g'),
        false,
        'Abbreviations like e.g. must not be extracted'
      );
      assert.strictEqual(
        extracted.includes('report.pdf'),
        false,
        'Document file extensions must not be extracted as domains'
      );
    });
  });

  // =========================================================================
  // 6. TECHNICAL URL ANOMALIES AS EVIDENCE & BOUNDED RISK
  // =========================================================================
  describe('6. Technical URL Anomalies Handling', () => {
    it('HTTP alone must NOT be treated as proof of fraud (score remains low)', () => {
      const url = 'http://ordinary-news-blog.org/articles/123';
      const res = analyzeDeterministic({ url });

      assert.strictEqual(res.assessment.level, 'low');
      assert.ok(res.assessment.score <= 15, `Score for HTTP alone should be low, got ${res.assessment.score}`);
    });

    it('Deep subdomain nesting alone must NOT be treated as proof of fraud', () => {
      const url = 'https://dev.portal.sub.internal.legit-company.com';
      const res = analyzeDeterministic({ url });

      assert.strictEqual(res.assessment.level, 'low');
      assert.ok(res.assessment.score <= 15);
    });

    it('Technical anomalies combined with brand spoofing produce suspicious threat assessment', () => {
      const url = 'http://alrajhi.portal.verify.attacker-server.xyz:8080/login';
      const res = analyzeDeterministic({ url });

      assert.ok(['suspicious', 'high'].includes(res.assessment.level));
      assert.ok(res.assessment.score >= 35, `Score expected >= 35, got ${res.assessment.score}`);
      assert.strictEqual(res.assessment.scamType, 'BANK_IMPERSONATION');
      assert.ok(res.detectedFeatures.includes('impersonation'));
      assert.ok(res.detectedFeatures.includes('suspicious_url'));
    });
  });

  // =========================================================================
  // 7. MULTIPLE URL HANDLING
  // =========================================================================
  describe('7. Multiple URL Aggregation', () => {
    it('Case 14: Benign first URL + malicious second URL must detect threat from second URL', () => {
      const text =
        'اقرأ مقالنا على https://general-news-portal.com/article ثم توجه للتحقق من حسابك عبر https://alrajhi.secure-login.xyz/verify فوراً.';
      const res = analyzeDeterministic({ text });

      // Verify both URLs were extracted and analyzed
      assert.strictEqual(res.urlResults.length, 2);
      assert.strictEqual(res.urlResults[0].hostname, 'general-news-portal.com');
      assert.strictEqual(res.urlResults[1].hostname, 'alrajhi.secure-login.xyz');

      // The malicious second URL must contribute evidence
      assert.strictEqual(
        res.detectedFeatures.includes('impersonation'),
        true,
        'Second URL impersonation must be captured in detectedFeatures'
      );
      assert.strictEqual(
        res.detectedFeatures.includes('suspicious_url'),
        true,
        'Second URL suspiciousness must be captured in detectedFeatures'
      );
      assert.strictEqual(res.assessment.scamType, 'BANK_IMPERSONATION');
      assert.strictEqual(res.assessment.level, 'high');

      // URL-specific findings must be preserved in assessment
      assert.ok(res.assessment.urlFindings);
      assert.strictEqual(res.assessment.urlFindings.totalUrls, 2);
      assert.strictEqual(res.assessment.urlFindings.suspiciousUrlsCount, 1);
      assert.strictEqual(res.assessment.urlFindings.urls[0].isSuspicious, false);
      assert.strictEqual(res.assessment.urlFindings.urls[1].isSuspicious, true);
    });
  });

  // =========================================================================
  // 8 & 9. EVIDENCE CONTRACT & SCAM DNA GROUNDING
  // =========================================================================
  describe('8 & 9. Evidence Contract & Scam DNA Grounding', () => {
    it('Scam DNA features must have concrete deterministic evidence items when activated', () => {
      const text =
        'عزيزي العميل، تم تجميد حسابك البنكي. أرسل رمز التحقق otp لتفادي إيقاف الخدمات فوراً.';
      const res = analyzeDeterministic({ text });

      assert.ok(res.assessment.featureEvidence);

      // Verify each detected feature has corresponding signals
      for (const feat of res.detectedFeatures) {
        const signals = res.assessment.featureEvidence[feat];
        assert.ok(signals && signals.length > 0, `Feature ${feat} must have non-empty signals in featureEvidence`);
        for (const sig of signals) {
          assert.strictEqual(sig.featureId, feat);
          assert.ok(sig.evidenceText.length > 0, 'Signal must have non-empty evidenceText');
          assert.ok(['text', 'url', 'rule'].includes(sig.source));
        }
      }

      // Verify inactive features have empty evidence lists
      const inactiveFeatures = (['financial_lure', 'secrecy_pressure'] as const).filter(
        (f) => !res.detectedFeatures.includes(f)
      );
      for (const feat of inactiveFeatures) {
        assert.strictEqual(
          res.assessment.featureEvidence[feat].length,
          0,
          `Inactive feature ${feat} must have empty evidence`
        );
      }
    });
  });

  // =========================================================================
  // 11. SECURITY REQUIREMENT: FULLY PASSIVE
  // =========================================================================
  describe('11. Security Principle: Zero Network Activity', () => {
    it('Deterministic analysis completes synchronously and purely offline', () => {
      const start = Date.now();
      const res = analyzeDeterministic({
        text: 'رسالة اختبارية مع رابط http://non-existent-domain-498172938127391.xyz/test',
      });
      const elapsed = Date.now() - start;

      // Pure string parsing takes < 50ms, no network timeout delays
      assert.ok(elapsed < 100, `Execution took ${elapsed}ms, indicating no network calls occurred`);
      assert.strictEqual(res.urlResults.length, 1);
      assert.strictEqual(res.urlResults[0].isSuspiciousTld, true);
    });
  });
});
