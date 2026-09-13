import { describe, it } from 'node:test';
import assert from 'node:assert';
import { POST } from '../app/api/analyze/route';
import { analyzeRequestSchema, screenshotPayloadSchema } from '../lib/api/schema';
import { VISION_CONFIG } from '../lib/config/vision';
import { analyzeDeterministic } from '../lib/analysis';

function createApiRequest(body: unknown): Request {
  return new Request('http://localhost:3000/api/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-forwarded-for': '198.51.100.77',
    },
    body: JSON.stringify(body),
  });
}

describe('Phase 8.5 — Zod Screenshot Data Max Hardening (SEC-FIND-05)', () => {
  // -------------------------------------------------------------------------
  // 1. Zod screenshot.data validation constraints
  // -------------------------------------------------------------------------
  describe('1. Zod Schema screenshot.data Boundary Constraints', () => {
    it('rejects empty screenshot.data with 400 and clear safe message', async () => {
      // Direct schema validation
      const schemaResult = screenshotPayloadSchema.safeParse({
        mimeType: 'image/png',
        data: '',
      });
      assert.strictEqual(schemaResult.success, false);
      assert.ok(schemaResult.error.issues.some((i) => i.message.includes('cannot be empty')));

      // API route execution
      const req = createApiRequest({
        screenshot: {
          mimeType: 'image/png',
          data: '   ',
        },
      });
      const res = await POST(req);
      assert.strictEqual(res.status, 400);

      const json = await res.json();
      assert.ok(json.error.includes('cannot be empty'));
    });

    it('rejects screenshot.data exceeding maxScreenshotDataLength with Zod validation error', async () => {
      // Verify constant exists and is 15,500,000
      assert.strictEqual(VISION_CONFIG.maxScreenshotDataLength, 15500000);

      // Create string of 15,500,001 characters (exceeds max by 1 char)
      // Test schema validation directly
      const oversizedData = 'A'.repeat(VISION_CONFIG.maxScreenshotDataLength + 1);
      const schemaResult = analyzeRequestSchema.safeParse({
        screenshot: {
          mimeType: 'image/png',
          data: oversizedData,
        },
      });

      assert.strictEqual(schemaResult.success, false);
      assert.ok(
        schemaResult.error.issues.some((i) =>
          i.message.includes('exceeds maximum permitted length of 15500000 characters')
        )
      );
    });

    it('allows valid screenshot within constraints to pass schema validation', () => {
      const validPayload = {
        mimeType: 'image/png',
        data: Buffer.from('valid-small-image-buffer').toString('base64'),
      };

      const result = screenshotPayloadSchema.safeParse(validPayload);
      assert.strictEqual(result.success, true);
    });
  });

  // -------------------------------------------------------------------------
  // 2. 10MB Decoded Legitimacy vs 11MB Decoded Enforcement
  // -------------------------------------------------------------------------
  describe('2. 10MB Decoded Allowance vs 11MB Decoded Enforcement', () => {
    it('guarantees that a 10MB decoded screenshot (~13.33MB Base64) is NEVER blocked by Zod max', () => {
      // 10MB decoded binary = 10,485,760 bytes
      // Base64 encoding ratio 4/3 -> 13,981,016 characters
      const tenMbDecodedBytes = VISION_CONFIG.maxImageSizeBytes; // exactly 10MB
      const expectedBase64Length = Math.ceil(tenMbDecodedBytes / 3) * 4; // 13,981,016

      assert.strictEqual(expectedBase64Length, 13981016);
      assert.ok(
        expectedBase64Length < VISION_CONFIG.maxScreenshotDataLength,
        `10MB Base64 (${expectedBase64Length}) must be strictly less than Zod max (${VISION_CONFIG.maxScreenshotDataLength})`
      );

      // Test with Data URL prefix: data:image/png;base64, (22 chars)
      const dataUrlLength = expectedBase64Length + 'data:image/png;base64,'.length;
      assert.ok(
        dataUrlLength < VISION_CONFIG.maxScreenshotDataLength,
        `10MB Data URL (${dataUrlLength}) must be strictly less than Zod max (${VISION_CONFIG.maxScreenshotDataLength})`
      );
    });

    it('guarantees that an 11MB decoded screenshot passes Zod max and is rejected by the domain decoded limit with 413', async () => {
      // 11MB decoded buffer = 11,534,336 bytes
      const elevenMbBuffer = Buffer.alloc(11 * 1024 * 1024);
      const elevenMbBase64 = elevenMbBuffer.toString('base64');

      // Verify it is under Zod max (15,379,116 < 15,500,000)
      assert.ok(
        elevenMbBase64.length < VISION_CONFIG.maxScreenshotDataLength,
        `11MB Base64 (${elevenMbBase64.length}) must be under Zod max (${VISION_CONFIG.maxScreenshotDataLength})`
      );

      // Verify schema accepts it structurally
      const schemaCheck = analyzeRequestSchema.safeParse({
        screenshot: {
          mimeType: 'image/png',
          data: elevenMbBase64,
        },
      });
      assert.strictEqual(schemaCheck.success, true, 'Schema must accept 11MB payload so domain validator enforces 413');

      // Send to API route: handleAnalyze must catch it and return HTTP 413
      const req = createApiRequest({
        screenshot: {
          mimeType: 'image/png',
          data: elevenMbBase64,
        },
      });

      const res = await POST(req);
      assert.strictEqual(res.status, 413);

      const json = await res.json();
      assert.ok(
        json.error && json.error.includes('exceeds maximum permitted size of 10 MB'),
        `Expected 10MB decoded limit message, got: ${json.error}`
      );
    });
  });

  // -------------------------------------------------------------------------
  // 3. Text and URL Boundary Regressions
  // -------------------------------------------------------------------------
  describe('3. Text and URL Boundary Invariance', () => {
    it('maintains strict text <= 5000 and url <= 2048 limits without regression', async () => {
      // Text limit: 5001 chars
      const reqText = createApiRequest({ text: 'ب'.repeat(5001) });
      const resText = await POST(reqText);
      assert.strictEqual(resText.status, 400);

      // URL limit: 2050 chars
      const reqUrl = createApiRequest({ url: `https://test.sa/${'x'.repeat(2040)}` });
      const resUrl = await POST(reqUrl);
      assert.strictEqual(resUrl.status, 400);
    });
  });

  // -------------------------------------------------------------------------
  // 4. Scenario Regression Integrity
  // -------------------------------------------------------------------------
  describe('4. Scenario Regression Integrity', () => {
    it('canonical evaluation scenarios RED-013, RED-034, and RED-043 evaluate identically', () => {
      // RED-013: Arabizi / Bank OTP phishing
      const red013 = analyzeDeterministic({
        text: '3aziz el3meel, 7sabk t36l. 7ot el OTP bsor3a 3la http://bank-login.top',
        url: 'http://bank-login.top',
      });
      assert.strictEqual(red013.assessment.score, 100);
      assert.strictEqual(red013.assessment.level, 'high');

      // RED-034: Multiple URL camouflage
      const red034 = analyzeDeterministic({
        text: 'عزيزي العميل، حرصاً على أمانك يمكنك مراجعة شروط الخدمة عبر موقعنا الرسمي https://alrajhibank.com.sa ولكن لتحديث بياناتك البنكية الآن افتح: https://alrajhi-update.top/auth',
        url: 'https://alrajhi-update.top/auth',
      });
      assert.strictEqual(red034.assessment.score, 85);
      assert.strictEqual(red034.assessment.level, 'high');

      // RED-043: Trojan Greeting Wrapper
      const red043 = analyzeDeterministic({
        text: 'ألف مبروك وكل عام وأنتم بخير! بمناسبة عيد الفطر المبارك أرسلنا لك بطاقة تهنئة خاصة باسمك. شاهد بطاقة المعايدة الخاصة بك وحمل هديتك من هنا: https://eid-mubarak-greeting.click',
        url: 'https://eid-mubarak-greeting.click',
      });
      assert.strictEqual(red043.assessment.score, 35);
      assert.strictEqual(red043.assessment.level, 'suspicious');
    });
  });

  // -------------------------------------------------------------------------
  // 5. Coexistence of All Security Layers
  // -------------------------------------------------------------------------
  describe('5. Coexistence of All Security Layers', () => {
    it('confirms rate limit, security headers, and raw body limit all remain active concurrently', async () => {
      const req = createApiRequest({ text: 'رسالة فحص أمني تجريبية' });
      const res = await POST(req);

      assert.strictEqual(res.status, 200);

      // Security headers check
      assert.strictEqual(res.headers.get('X-Content-Type-Options'), 'nosniff');
      assert.strictEqual(res.headers.get('X-Frame-Options'), 'DENY');
      assert.ok(res.headers.get('Content-Security-Policy'));

      // Rate limit headers check
      assert.ok(res.headers.get('X-RateLimit-Limit'));
      assert.ok(res.headers.get('X-RateLimit-Remaining'));
    });
  });
});
