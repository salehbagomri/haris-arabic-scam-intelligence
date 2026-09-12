/**
 * HARIS (حارس) — Phase 5A: Unified Analysis API Tests
 *
 * Comprehensive API-level test suite for POST /api/analyze:
 * 1. text-only legitimate message -> 200
 * 2. text-only obvious scam -> 200
 * 3. URL-only suspicious URL -> 200
 * 4. screenshot-only successful analysis -> 200
 * 5. screenshot-only extraction failure -> 200 with structured failure state
 * 6. text + screenshot fallback -> 200
 * 7. multiple inputs coexistence -> 200
 * 8. empty request -> 400
 * 9. malformed payload -> 400
 * 10. oversized screenshot -> 413
 * 11. unsupported screenshot MIME -> 400
 * 12. verify user URLs are not fetched (zero network/HTTP calls)
 * 13. verify sensitive payloads are not logged
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { POST, setAnalyzePipelineForTesting } from '../app/api/analyze/route';
import { setGeminiClientForTesting, resetGeminiClientCache } from '../lib/ai/client';
import { AnalyzeResponse, analyzeResponseSchema } from '../lib/api/schema';
import { VISION_CONFIG } from '../lib/config/vision';

describe('HARIS Phase 5A: Unified Analysis API (POST /api/analyze)', () => {
  beforeEach(() => {
    resetGeminiClientCache();
    setAnalyzePipelineForTesting(null);
  });

  afterEach(() => {
    resetGeminiClientCache();
    setAnalyzePipelineForTesting(null);
  });

  // Helper to create Request object
  function createApiRequest(body: unknown, isRawString = false): Request {
    return new Request('http://localhost:3000/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: isRawString ? (body as string) : JSON.stringify(body),
    });
  }

  // =========================================================================
  // 1. Text-only Legitimate Message
  // =========================================================================
  it('1. text-only legitimate message returns 200 with low risk score', async () => {
    const req = createApiRequest({
      text: 'السلام عليكم ورحمة الله، كيف حالك أخي الكريم؟ طمني عن صحتك وأحوال العائلة.',
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);

    const data = (await res.json()) as AnalyzeResponse;
    const validation = analyzeResponseSchema.safeParse(data);
    assert.strictEqual(validation.success, true);
    assert.strictEqual(data.riskLevel, 'low');
    assert.ok(data.riskScore <= 15);
    assert.strictEqual(data.isExtractionFailure, false);
  });

  // =========================================================================
  // 2. Text-only Obvious Scam
  // =========================================================================
  it('2. text-only obvious scam returns 200 with high risk and BANK_IMPERSONATION', async () => {
    const req = createApiRequest({
      text: 'عزيزي العميل، تم إيقاف حسابك في مصرف الراجحي، أرسل رمز التحقق OTP فوراً لتفعيل البطاقة.',
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);

    const data = (await res.json()) as AnalyzeResponse;
    assert.strictEqual(data.riskLevel, 'high');
    assert.ok(data.riskScore >= 70);
    assert.strictEqual(data.scamType, 'BANK_IMPERSONATION');
    const otpDna = data.scamDna.find((d) => d.featureId === 'otp_request');
    assert.ok(otpDna && otpDna.detected);
  });

  // =========================================================================
  // 3. URL-only Suspicious URL
  // =========================================================================
  it('3. URL-only suspicious URL returns 200 and flags subdomain brand spoofing', async () => {
    const req = createApiRequest({
      url: 'https://alrajhi.secure-login.xyz/verify',
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);

    const data = (await res.json()) as AnalyzeResponse;
    assert.strictEqual(data.riskLevel, 'suspicious');
    assert.ok(data.riskScore >= 30);
    assert.ok(data.evidence.some((e) => e.title.includes('الراجحي') || e.title.includes('نطاق') || e.title.includes('خداع')));
  });

  // =========================================================================
  // 4. Screenshot-only Successful Analysis
  // =========================================================================
  it('4. screenshot-only successful analysis returns 200 with visual and extracted findings', async () => {
    const mockVisionPayload = {
      extractedText: 'تم إيقاف حسابك البنكي، اضغط الرابط للتفعيل: https://bank.secure-login.xyz',
      extractedUrls: ['https://bank.secure-login.xyz'],
      visibleEntities: [
        { type: 'brand_logo', text: 'البنك الأهلي', confidence: 0.9 },
      ],
      visualSignals: [
        {
          type: 'fake_security_warning',
          description: 'إشعار تعليق أمني لإثارة القلق',
          evidence: 'تم إيقاف حسابك البنكي',
          severity: 'high',
        },
      ],
      uncertainties: [],
      extractionConfidence: 0.92,
    };

    const mockClient = {
      models: {
        generateContent: async () => ({ text: JSON.stringify(mockVisionPayload) }),
      },
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setGeminiClientForTesting(mockClient as any);

    const req = createApiRequest({
      screenshot: {
        mimeType: 'image/png',
        data: Buffer.from('mock-valid-png-content').toString('base64'),
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);

    const data = (await res.json()) as AnalyzeResponse;
    assert.strictEqual(data.isExtractionFailure, false);
    assert.strictEqual(data.extractionConfidence, 0.92);
    assert.ok(data.evidence.some((e) => e.source === 'visual' || e.source === 'technical'));
  });

  // =========================================================================
  // 5. Screenshot-only Extraction Failure
  // =========================================================================
  it('5. screenshot-only extraction failure returns 200 with explicit failure state', async () => {
    // Failing vision client
    const failingClient = {
      models: {
        generateContent: async () => {
          throw new Error('Gemini vision API timeout after 15000ms');
        },
      },
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setGeminiClientForTesting(failingClient as any);

    const req = createApiRequest({
      screenshot: {
        mimeType: 'image/png',
        data: Buffer.from('some-image-data').toString('base64'),
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);

    const data = (await res.json()) as AnalyzeResponse;
    assert.strictEqual(data.isExtractionFailure, true);
    assert.ok(data.interpretation.includes('تعذر استخراج أو قراءة محتوى لقطة الشاشة'));
    assert.ok(!data.interpretation.includes('لم يتم رصد أي مؤشرات احتيال واضحة'));
    assert.ok(data.uncertainties.some((u) => u.includes('timed out') || u.includes('timeout')));
    assert.ok(data.actionableAdvice.some((a) => a.includes('لقطة شاشة') || a.includes('نسخ نص')));
  });

  // =========================================================================
  // 6. Text + Screenshot Fallback
  // =========================================================================
  it('6. text + screenshot fallback executes text analysis when vision fails', async () => {
    const failingClient = {
      models: {
        generateContent: async () => {
          throw new Error('Vision gateway error 503');
        },
      },
    };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    setGeminiClientForTesting(failingClient as any);

    const req = createApiRequest({
      text: 'أرسل لي رمز التحقق OTP فوراً لتحديث الحساب.',
      screenshot: {
        mimeType: 'image/png',
        data: Buffer.from('some-data').toString('base64'),
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);

    const data = (await res.json()) as AnalyzeResponse;
    assert.strictEqual(data.isExtractionFailure, false);
    assert.ok(data.riskScore > 0);
    const otpDna = data.scamDna.find((d) => d.featureId === 'otp_request');
    assert.ok(otpDna && otpDna.detected);
    assert.ok(data.uncertainties.some((u) => u.includes('فشل استخراج')));
  });

  // =========================================================================
  // 7. Multiple Inputs Coexistence
  // =========================================================================
  it('7. multiple inputs (text + URL) coexist and unify threat findings', async () => {
    const req = createApiRequest({
      text: 'عزيزي العميل، يرجى مراجعة الرابط أدناه وإدخال كلمة المرور.',
      url: 'https://alrajhi.secure-login.xyz/login',
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);

    const data = (await res.json()) as AnalyzeResponse;
    assert.strictEqual(data.riskLevel, 'high');
    assert.ok(
      data.evidence.some(
        (e) => e.title.includes('الراجحي') || e.title.includes('كلمات المرور') || e.title.includes('خداع')
      )
    );
    assert.ok(data.scamDna.some((d) => d.featureId === 'credential_request' && d.detected));
    assert.ok(data.scamDna.some((d) => d.featureId === 'suspicious_url' && d.detected));
  });

  // =========================================================================
  // 8. Empty Request -> 400
  // =========================================================================
  it('8. empty request returns 400 Bad Request', async () => {
    const req = createApiRequest({});
    const res = await POST(req);
    assert.strictEqual(res.status, 400);

    const body = (await res.json()) as { error: string };
    assert.ok(body.error && body.error.includes('Request must include at least one valid input'));
  });

  // =========================================================================
  // 9. Malformed Payload -> 400
  // =========================================================================
  it('9. malformed JSON payload returns 400 Bad Request', async () => {
    const req = createApiRequest('{"text": "broken json syntax...', true);
    const res = await POST(req);
    assert.strictEqual(res.status, 400);

    const body = (await res.json()) as { error: string };
    assert.ok(body.error && body.error.includes('Invalid JSON payload'));
  });

  // =========================================================================
  // 10. Oversized Screenshot -> 413
  // =========================================================================
  it('10. oversized screenshot returns 413 Payload Too Large', async () => {
    // 11 MB buffer
    const hugeBuffer = Buffer.alloc(VISION_CONFIG.maxImageSizeBytes + 1024 * 1024);
    const req = createApiRequest({
      screenshot: {
        mimeType: 'image/png',
        data: hugeBuffer.toString('base64'),
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 413);

    const body = (await res.json()) as { error: string };
    assert.ok(body.error && body.error.includes('exceeds maximum permitted size'));
  });

  // =========================================================================
  // 11. Unsupported Screenshot MIME -> 400
  // =========================================================================
  it('11. unsupported screenshot MIME returns 400 Bad Request', async () => {
    const req = createApiRequest({
      screenshot: {
        mimeType: 'application/pdf',
        data: Buffer.from('pdf-data').toString('base64'),
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 400);

    const body = (await res.json()) as { error: string };
    assert.ok(body.error && body.error.includes('Unsupported screenshot MIME type'));
  });

  // =========================================================================
  // 12. Verify User URLs are Not Fetched
  // =========================================================================
  it('12. verifies user URLs are never fetched (zero network requests)', async () => {
    const targetUrl = 'https://malicious-probe-test-xyz-999.com/phish';
    let fetchCalled = false;

    // Spy on global fetch
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      const urlString = String(input);
      if (urlString.includes('malicious-probe-test-xyz-999')) {
        fetchCalled = true;
      }
      return originalFetch(input, init);
    };

    try {
      const req = createApiRequest({ url: targetUrl });
      const res = await POST(req);
      assert.strictEqual(res.status, 200);
      assert.strictEqual(fetchCalled, false, 'Expected user URL to NEVER be fetched by any subsystem');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  // =========================================================================
  // 13. Verify Sensitive Payloads are Not Logged
  // =========================================================================
  it('13. verifies sensitive user payloads (OTPs, passwords) are not logged', async () => {
    const sensitiveOtp = 'SECRET_OTP_998877';
    const sensitivePass = 'SUPER_CONFIDENTIAL_PASS_123';
    const loggedMessages: string[] = [];

    const intercept = (...args: unknown[]) => {
      loggedMessages.push(args.map((a) => String(a)).join(' '));
    };

    const origLog = console.log;
    const origWarn = console.warn;
    const origError = console.error;
    const origInfo = console.info;

    console.log = intercept;
    console.warn = intercept;
    console.error = intercept;
    console.info = intercept;

    try {
      const req = createApiRequest({
        text: `رمز التحقق هو ${sensitiveOtp} وكلمة المرور ${sensitivePass}`,
      });

      const res = await POST(req);
      assert.strictEqual(res.status, 200);

      for (const logLine of loggedMessages) {
        assert.strictEqual(
          logLine.includes(sensitiveOtp),
          false,
          `Found sensitive OTP in console log: "${logLine}"`
        );
        assert.strictEqual(
          logLine.includes(sensitivePass),
          false,
          `Found sensitive password in console log: "${logLine}"`
        );
      }
    } finally {
      console.log = origLog;
      console.warn = origWarn;
      console.error = origError;
      console.info = origInfo;
    }
  });

  // =========================================================================
  // Phase 5A.1 Precision Patch Tests
  // =========================================================================

  // 1. Base64 & Data URL Validation (Finding 1)
  it('14. malformed Base64 payload returns 400 Bad Request', async () => {
    const req = createApiRequest({
      screenshot: {
        mimeType: 'image/png',
        data: 'not_valid_base64!!!@#$',
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 400);

    const body = (await res.json()) as { error: string };
    assert.ok(body.error && body.error.includes('Base64'));
  });

  it('15. non-canonical Base64 payload with invalid padding returns 400', async () => {
    const req = createApiRequest({
      screenshot: {
        mimeType: 'image/png',
        data: 'AAAA===', // invalid padding (3 equals)
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 400);

    const body = (await res.json()) as { error: string };
    assert.ok(body.error && body.error.includes('Base64'));
  });

  it('16. valid canonical Base64 payload is accepted with 200', async () => {
    const validBase64 = Buffer.from('HARIS-valid-test-image-bytes').toString('base64');
    const req = createApiRequest({
      screenshot: {
        mimeType: 'image/png',
        data: validBase64,
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);
  });

  it('17. valid Data URL with matching MIME is accepted with 200', async () => {
    const validBase64 = Buffer.from('HARIS-test-png-data').toString('base64');
    const req = createApiRequest({
      screenshot: {
        mimeType: 'image/png',
        data: `data:image/png;base64,${validBase64}`,
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);
  });

  it('18. Data URL MIME mismatch with screenshot.mimeType returns 400', async () => {
    const validBase64 = Buffer.from('HARIS-test-png-data').toString('base64');
    const req = createApiRequest({
      screenshot: {
        mimeType: 'image/png',
        data: `data:image/jpeg;base64,${validBase64}`,
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 400);

    const body = (await res.json()) as { error: string };
    assert.ok(body.error && body.error.includes('Data URL MIME type'));
  });

  // 2. Strict Zod Schemas (Finding 2)
  it('19. unexpected top-level request field is rejected with 400 (strict validation)', async () => {
    const req = createApiRequest({
      text: 'السلام عليكم ورحمة الله',
      unexpectedField: 'malicious-injection',
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 400);

    const body = (await res.json()) as { error: string };
    assert.ok(
      body.error &&
        (body.error.includes('unexpectedField') ||
          body.error.includes('Unrecognized') ||
          body.error.includes('unrecognized_keys'))
    );
  });

  it('20. unexpected screenshot property is rejected with 400 (strict validation)', async () => {
    const validBase64 = Buffer.from('HARIS-test-png-data').toString('base64');
    const req = createApiRequest({
      screenshot: {
        mimeType: 'image/png',
        data: validBase64,
        extraUnauthorizedProperty: true,
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 400);

    const body = (await res.json()) as { error: string };
    assert.ok(
      body.error &&
        (body.error.includes('extraUnauthorizedProperty') ||
          body.error.includes('Unrecognized') ||
          body.error.includes('unrecognized_keys'))
    );
  });

  // 3. Exact MIME Allowlist (Finding 3)
  it('21. accepts all approved MIME types in VISION_CONFIG allowlist', async () => {
    const validBase64 = Buffer.from('HARIS-test-image-content').toString('base64');
    const approvedMimes = ['image/png', 'image/jpeg', 'image/webp', 'image/heic', 'image/gif'] as const;

    for (const mime of approvedMimes) {
      const req = createApiRequest({
        screenshot: {
          mimeType: mime,
          data: validBase64,
        },
      });

      const res = await POST(req);
      assert.strictEqual(res.status, 200, `Expected approved MIME ${mime} to return 200`);
    }
  });

  it('22. rejects unsupported MIME types including image/heif, image/svg+xml, and text/plain with 400', async () => {
    const validBase64 = Buffer.from('HARIS-test-image-content').toString('base64');
    const disallowedMimes = ['image/heif', 'image/svg+xml', 'image/bmp', 'text/plain'];

    for (const mime of disallowedMimes) {
      const req = createApiRequest({
        screenshot: {
          mimeType: mime,
          data: validBase64,
        },
      });

      const res = await POST(req);
      assert.strictEqual(res.status, 400, `Expected disallowed MIME ${mime} to return 400`);

      const body = (await res.json()) as { error: string };
      assert.ok(body.error && body.error.includes('Unsupported screenshot MIME type'));
    }
  });

  // 4. Complete HTTP 500 Error Coverage (Finding 4)
  it('23. unexpected server exception returns HTTP 500 without leaking stack traces, keys, or internals', async () => {
    const secretApiKey = 'AIzaSySecretApiKeyThatMustNeverLeak12345';
    const internalTrace = 'Error: Kernel Panic at /internal/secrets/vault.ts:42:15';

    setAnalyzePipelineForTesting(async () => {
      throw new Error(`${internalTrace} with key ${secretApiKey}`);
    });

    try {
      const req = createApiRequest({ text: 'تحقق من حسابك فوراً' });
      const res = await POST(req);
      assert.strictEqual(res.status, 500);

      const body = (await res.json()) as Record<string, unknown>;
      // Must be a stable JSON error shape with only 'error'
      assert.deepStrictEqual(Object.keys(body), ['error']);
      assert.strictEqual(typeof body.error, 'string');
      assert.strictEqual(body.error, 'An unexpected internal error occurred during analysis.');

      // Verification: zero leak of keys, stack traces, or internal paths
      const errorStr = body.error as string;
      assert.strictEqual(errorStr.includes(secretApiKey), false, 'API key leaked in 500 response!');
      assert.strictEqual(errorStr.includes('Kernel Panic'), false, 'Stack trace leaked in 500 response!');
      assert.strictEqual(errorStr.includes('/internal/'), false, 'Internal path leaked in 500 response!');
      assert.strictEqual(errorStr.includes('vault.ts'), false, 'Internal filename leaked in 500 response!');
    } finally {
      setAnalyzePipelineForTesting(null);
    }
  });
});
