import { describe, it } from 'node:test';
import assert from 'node:assert';
import { analyzeUnified } from '../lib/vision/pipeline';
import { POST } from '../app/api/analyze/route';
import { analyzeDeterministic } from '../lib/analysis';
import { setGeminiClientForTesting } from '../lib/ai/client';

function createApiRequest(body: unknown): Request {
  return new Request('http://localhost:3000/api/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-forwarded-for': '198.51.100.42',
    },
    body: JSON.stringify(body),
  });
}

describe('Phase 8.2 — Error Leakage Hardening (SEC-FIND-02)', () => {
  const dummyBuffer = Buffer.from('fake-png-image-header-data-for-testing-1234567890');
  const sensitiveUserText = 'كلمة المرور السرية للمستخدم هي: [P@ssword_SECRET_9999] ورقم الحساب: 1234567890';

  // -------------------------------------------------------------------------
  // 1. Missing GEMINI_API_KEY Simulation
  // -------------------------------------------------------------------------
  describe('1. Missing GEMINI_API_KEY', () => {
    it('screenshot-only analysis with missing client returns safe Arabic messages without leaking config/env details', async () => {
      const result = await analyzeUnified(
        {
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        { client: null } // Simulates GEMINI_API_KEY missing or empty
      );

      assert.strictEqual(result.isExtractionFailure, true);
      assert.strictEqual(result.riskScore, 0);
      assert.strictEqual(result.riskLevel, 'low');

      // Interpretation must NOT contain raw error or parenthesis
      assert.strictEqual(
        result.interpretation,
        'تعذر استخراج أو قراءة محتوى لقطة الشاشة المرفقة. لم يتم التحقق من سلامة المحتوى ولا يعتبر ذلك مؤشراً على أمان الرسالة.'
      );

      // Uncertainties must NOT leak GEMINI_API_KEY or provider details
      for (const unc of result.uncertainties) {
        assert.strictEqual(unc.includes('GEMINI_API_KEY'), false, 'Must not leak GEMINI_API_KEY');
        assert.strictEqual(unc.includes('Gemini'), false, 'Must not leak provider name Gemini');
        assert.strictEqual(unc.includes('Google'), false, 'Must not leak Google');
        assert.strictEqual(unc.includes('process.env'), false, 'Must not leak process.env');
      }

      assert.ok(result.uncertainties.some((u) => u.includes('فشل استخراج محتوى لقطة الشاشة')));
      assert.ok(result.uncertainties.some((u) => u.includes('ولا تعني بأي حال من الأحوال أن الرسالة آمنة')));
    });

    it('text analysis with missing client completes deterministic assessment with safe AI notice', async () => {
      const result = await analyzeUnified(
        {
          text: 'عزيزي العميل، تم تجميد حسابك البنكي. يرجى إرسال رمز OTP فوراً.',
        },
        { client: null }
      );

      assert.strictEqual(result.isExtractionFailure, false);
      assert.ok(result.riskScore >= 80, 'Deterministic engine must score scam independently');
      assert.ok(result.detectedFeatures.includes('otp_request'));

      // Uncertainties must contain safe Arabic disclaimer
      assert.ok(
        result.uncertainties.some((u) =>
          u.includes('لم يتم تطبيق التحليل الدلالي بالذكاء الاصطناعي في هذا الفحص')
        )
      );

      for (const unc of result.uncertainties) {
        assert.strictEqual(unc.includes('GEMINI_API_KEY'), false);
        assert.strictEqual(unc.includes('Gemini'), false);
      }
    });
  });

  // -------------------------------------------------------------------------
  // 2. Gemini / Provider Exception Simulation
  // -------------------------------------------------------------------------
  describe('2. Gemini / Provider Exception Simulation', () => {
    it('shields client from raw provider errors, 403 Forbidden, and network stack traces', async () => {
      const failingClient = {
        models: {
          generateContent: async () => {
            throw new Error(
              'GoogleGenAIError: [403 Forbidden] API key not valid. Please pass a valid API key. At https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent\n    at Client.call (c:\\my_projects\\haris\\node_modules\\@google\\genai\\dist\\index.js:123:45)'
            );
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

      // Verify ZERO provider leakages in all user-facing strings
      const serialized = JSON.stringify({
        interpretation: result.interpretation,
        uncertainties: result.uncertainties,
        advice: result.actionableAdvice,
      });

      assert.strictEqual(serialized.includes('GoogleGenAIError'), false);
      assert.strictEqual(serialized.includes('403 Forbidden'), false);
      assert.strictEqual(serialized.includes('generativelanguage.googleapis.com'), false);
      assert.strictEqual(serialized.includes('node_modules'), false);
      assert.strictEqual(serialized.includes('c:\\my_projects'), false);
      assert.strictEqual(serialized.includes('API key not valid'), false);

      assert.ok(result.uncertainties.some((u) => u.includes('فشل استخراج محتوى لقطة الشاشة')));
    });

    it('shields client from connection timeout without leaking internal threshold or ms counter', async () => {
      const timeoutClient = {
        models: {
          generateContent: async () => {
            throw new Error('Connection timeout abort signal triggered after 15000ms at internal host 10.0.0.1:443');
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
        { client: timeoutClient as any }
      );

      assert.strictEqual(result.isExtractionFailure, true);
      const serialized = JSON.stringify(result.uncertainties);

      assert.strictEqual(serialized.includes('10.0.0.1'), false);
      assert.strictEqual(serialized.includes('15000ms'), false);
      assert.ok(result.uncertainties.some((u) => u.includes('انتهت المهلة الزمنية المحددة للتحليل البصري')));
    });
  });

  // -------------------------------------------------------------------------
  // 3. Screenshot Extraction Failure Semantics
  // -------------------------------------------------------------------------
  describe('3. Screenshot Extraction Failure Semantics', () => {
    it('maintains isExtractionFailure: false when text/URL input succeeds alongside failing screenshot', async () => {
      const failingClient = {
        models: {
          generateContent: async () => {
            throw new Error('Internal vision crash');
          },
        },
      };

      const result = await analyzeUnified(
        {
          text: 'أدخل كود التحقق OTP لتحديث بياناتك البنكية.',
          url: 'https://alrajhi-update.top/auth',
          screenshot: {
            buffer: dummyBuffer,
            mimeType: 'image/png',
          },
        },
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        { client: failingClient as any }
      );

      // Must NOT mark as total extraction failure because text is present and valid
      assert.strictEqual(result.isExtractionFailure, false);
      assert.ok(result.riskScore > 50, 'Threats in text/URL must still be evaluated');
      assert.ok(result.detectedFeatures.includes('otp_request'));

      // Uncertainties must include safe warning that screenshot extraction failed and analysis used text/URL
      assert.ok(
        result.uncertainties.some(
          (u) =>
            u.includes('فشل استخراج لقطة الشاشة') &&
            u.includes('واعتمد التحليل على النص/الرابط المدخل فقط')
        )
      );

      // Must NOT leak 'Internal vision crash'
      const serialized = JSON.stringify(result.uncertainties);
      assert.strictEqual(serialized.includes('Internal vision crash'), false);
    });
  });

  // -------------------------------------------------------------------------
  // 4. Privacy: Zero User Content / Image Leakage in Errors
  // -------------------------------------------------------------------------
  describe('4. Privacy: Zero User Content / Image Leakage', () => {
    it('ensures user sensitive message text never reflects into error messages or uncertainties', async () => {
      const failingClient = {
        models: {
          generateContent: async () => {
            throw new Error('Failure during processing');
          },
        },
      };

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      setGeminiClientForTesting(failingClient as any);
      try {
        const req = createApiRequest({
          text: sensitiveUserText,
          screenshot: {
            mimeType: 'image/png',
            data: dummyBuffer.toString('base64'),
          },
        });

        // Execute route with failing client
        const res = await POST(req);
        assert.strictEqual(res.status, 200);

        const json = await res.json();
        const serialized = JSON.stringify({
          uncertainties: json.uncertainties,
          interpretation: json.interpretation,
          error: json.error,
        });

        assert.strictEqual(
          serialized.includes('[P@ssword_SECRET_9999]'),
          false,
          'Sensitive user text must NEVER leak into error/uncertainties metadata'
        );
        assert.strictEqual(
          serialized.includes('1234567890'),
          false,
          'Sensitive account number must NEVER leak into error/uncertainties metadata'
        );
      } finally {
        setGeminiClientForTesting(null);
      }
    });
  });

  // -------------------------------------------------------------------------
  // 5. Scenario Regression Integrity
  // -------------------------------------------------------------------------
  describe('5. Scenario Regression Integrity', () => {
    it('RED-013: Arabizi / Bank OTP phishing produces HIGH / 100', () => {
      const red013 = analyzeDeterministic({
        text: '3aziz el3meel, 7sabk t36l. 7ot el OTP bsor3a 3la http://bank-login.top',
        url: 'http://bank-login.top',
      });
      assert.strictEqual(red013.assessment.score, 100);
      assert.strictEqual(red013.assessment.level, 'high');
    });

    it('RED-034: Multiple URL camouflage produces HIGH / 85', () => {
      const red034 = analyzeDeterministic({
        text: 'عزيزي العميل، حرصاً على أمانك يمكنك مراجعة شروط الخدمة عبر موقعنا الرسمي https://alrajhibank.com.sa ولكن لتحديث بياناتك البنكية الآن افتح: https://alrajhi-update.top/auth',
        url: 'https://alrajhi-update.top/auth',
      });
      assert.strictEqual(red034.assessment.score, 85);
      assert.strictEqual(red034.assessment.level, 'high');
    });

    it('RED-043: Trojan Greeting Wrapper produces SUSPICIOUS / 35', () => {
      const red043 = analyzeDeterministic({
        text: 'ألف مبروك وكل عام وأنتم بخير! بمناسبة عيد الفطر المبارك أرسلنا لك بطاقة تهنئة خاصة باسمك. شاهد بطاقة المعايدة الخاصة بك وحمل هديتك من هنا: https://eid-mubarak-greeting.click',
        url: 'https://eid-mubarak-greeting.click',
      });
      assert.strictEqual(red043.assessment.score, 35);
      assert.strictEqual(red043.assessment.level, 'suspicious');
    });
  });
});
