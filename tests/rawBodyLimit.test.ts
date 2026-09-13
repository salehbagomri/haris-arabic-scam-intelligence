import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { POST, setAnalyzePipelineForTesting, setRawBodyLimitBytesForTesting } from '../app/api/analyze/route';
import { analyzeDeterministic } from '../lib/analysis';

function createApiRequest(body: unknown, headers: Record<string, string> = {}): Request {
  const bodyString = typeof body === 'string' ? body : JSON.stringify(body);
  return new Request('http://localhost:3000/api/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-forwarded-for': '198.51.100.99',
      ...headers,
    },
    body: bodyString,
  });
}

describe('Phase 8.3 — Raw Body Limit Hardening (SEC-FIND-03)', () => {
  beforeEach(() => {
    setAnalyzePipelineForTesting(null);
    setRawBodyLimitBytesForTesting(null);
  });

  afterEach(() => {
    setAnalyzePipelineForTesting(null);
    setRawBodyLimitBytesForTesting(null);
  });

  // -------------------------------------------------------------------------
  // 1. Request Body Smaller than Limit -> 200 OK
  // -------------------------------------------------------------------------
  it('1. request body smaller than limit succeeds and processes normally', async () => {
    const req = createApiRequest({
      text: 'عزيزي العميل، تم إيداع الراتب في حسابك البنكي بنجاح.',
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);

    const json = await res.json();
    assert.strictEqual(json.riskLevel, 'low');
    assert.strictEqual(json.riskScore, 0);
  });

  // -------------------------------------------------------------------------
  // 2. Request Body Exceeds Limit via Content-Length Fast-Path -> 413
  // -------------------------------------------------------------------------
  it('2. request with Content-Length exceeding 16MB is rejected with 413 before reading stream', async () => {
    let pipelineCalled = false;
    setAnalyzePipelineForTesting(async () => {
      pipelineCalled = true;
      throw new Error('Pipeline must NEVER be called for oversized body');
    });

    // Send a request declaring 20MB Content-Length
    const req = createApiRequest(
      { text: 'test' },
      { 'content-length': String(20 * 1024 * 1024) }
    );

    const res = await POST(req);
    assert.strictEqual(res.status, 413);
    assert.strictEqual(pipelineCalled, false, 'Pipeline must not be invoked');

    const json = await res.json();
    assert.strictEqual(
      json.error,
      'حجم حمولة الطلب يتجاوز الحد الأقصى المسموح به (16 ميجابايت).'
    );

    // Rate limit headers must still be present
    assert.ok(res.headers.get('X-RateLimit-Limit'));
    assert.ok(res.headers.get('X-RateLimit-Remaining'));
  });

  // -------------------------------------------------------------------------
  // 3. Incremental Stream Abort on Chunk Overflow -> 413
  // -------------------------------------------------------------------------
  it('3. incremental stream reader aborts reading and cancels stream as soon as limit is exceeded', async () => {
    let pipelineCalled = false;
    setAnalyzePipelineForTesting(async () => {
      pipelineCalled = true;
      throw new Error('Pipeline must NEVER be called for oversized body');
    });

    // Set a tight limit of 300 bytes for testing incremental stream guard
    setRawBodyLimitBytesForTesting(300);

    // Payload is ~600 bytes
    const oversizedPayload = {
      text: 'أ'.repeat(250), // 250 Arabic characters = 500 UTF-8 bytes
    };

    const req = createApiRequest(oversizedPayload);

    const res = await POST(req);
    assert.strictEqual(res.status, 413);
    assert.strictEqual(pipelineCalled, false, 'Pipeline must not be invoked');

    const json = await res.json();
    assert.strictEqual(
      json.error,
      'حجم حمولة الطلب يتجاوز الحد الأقصى المسموح به (16 ميجابايت).'
    );
  });

  // -------------------------------------------------------------------------
  // 4. Proof: Oversized Payload Never Reaches JSON Parsing
  // -------------------------------------------------------------------------
  it('4. malformed or malicious payload that exceeds limit is dropped with 413 before JSON parsing', async () => {
    setRawBodyLimitBytesForTesting(200);

    // Intentionally invalid JSON with 500 bytes of garbage
    const garbagePayload = 'INVALID_JSON_STREAM_DATA_OVERFLOW_'.repeat(20);

    const req = new Request('http://localhost:3000/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-forwarded-for': '198.51.100.101',
      },
      body: garbagePayload,
    });

    const res = await POST(req);
    // Must return 413 Payload Too Large, NOT 400 Invalid JSON!
    // This strictly proves that the byte limit check precedes JSON parsing!
    assert.strictEqual(res.status, 413);

    const json = await res.json();
    assert.strictEqual(
      json.error,
      'حجم حمولة الطلب يتجاوز الحد الأقصى المسموح به (16 ميجابايت).'
    );
  });

  // -------------------------------------------------------------------------
  // 5. Screenshot Decoded > 10MB Retains Existing Domain Validation
  // -------------------------------------------------------------------------
  it('5. screenshot payload with decoded size > 10MB retains existing domain validation', async () => {
    // 10.5 MB decoded image buffer -> ~14 MB Base64 string (within the 16MB raw HTTP body limit)
    const elevenMbBuffer = Buffer.alloc(10.5 * 1024 * 1024);
    const req = createApiRequest({
      screenshot: {
        mimeType: 'image/png',
        data: elevenMbBuffer.toString('base64'),
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 413);

    const json = await res.json();
    // Domain validation message from handleAnalyze is preserved
    assert.ok(
      json.error && json.error.includes('exceeds maximum permitted size of 10 MB'),
      `Expected domain 10MB message, got: ${json.error}`
    );
  });

  // -------------------------------------------------------------------------
  // 6. Screenshot within limits succeeds
  // -------------------------------------------------------------------------
  it('6. screenshot within limits passes through raw body guard and processes normally', async () => {
    const validImageBuffer = Buffer.alloc(100 * 1024, 0x41); // 100 KB
    const req = createApiRequest({
      text: 'يرجى مراجعة الصورة المرفقة للفحص.',
      screenshot: {
        mimeType: 'image/png',
        data: validImageBuffer.toString('base64'),
      },
    });

    const res = await POST(req);
    assert.strictEqual(res.status, 200);
    const json = await res.json();
    assert.ok(json.riskLevel);
  });

  // -------------------------------------------------------------------------
  // 7. Field Limits (text <= 5000, url <= 2048) Remain Intact
  // -------------------------------------------------------------------------
  it('7. text > 5000 chars and url > 2048 chars remain strictly rejected by field limits', async () => {
    // Text limit check
    const reqOversizedText = createApiRequest({
      text: 'أ'.repeat(5001),
    });
    const resText = await POST(reqOversizedText);
    assert.strictEqual(resText.status, 400);
    const jsonText = await resText.json();
    assert.ok(jsonText.error.includes('5000'));

    // URL limit check
    const reqOversizedUrl = createApiRequest({
      url: `https://example.com/${'a'.repeat(2050)}`,
    });
    const resUrl = await POST(reqOversizedUrl);
    assert.strictEqual(resUrl.status, 400);
    const jsonUrl = await resUrl.json();
    assert.ok(jsonUrl.error.includes('2048'));
  });

  // -------------------------------------------------------------------------
  // 8. Scenario Regression Integrity
  // -------------------------------------------------------------------------
  it('8. canonical evaluation scenarios RED-013, RED-034, and RED-043 evaluate identically', () => {
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
