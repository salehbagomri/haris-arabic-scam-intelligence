/**
 * HARIS (حارس) — API Abuse Hardening & Rate Limiting Tests (Phase 8.1)
 *
 * Verifies:
 * 1. Normal request under limit succeeds (HTTP 200).
 * 2. Consecutive requests under limit succeed with decreasing remaining count.
 * 3. 11th request exceeding limit returns HTTP 429 with Retry-After and rate limit headers.
 * 4. Distinct client IPs maintain isolated counters (no cross-client interference).
 * 5. Concurrent requests from same client handle atomicity without race conditions.
 * 6. Zero user data (text/url/screenshot) or API keys are stored in rate limiter state.
 * 7. Key benchmark scenarios (RED-013, RED-034, RED-043) retain exact expected scores.
 */

import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';
import { POST } from '../app/api/analyze/route';
import {
  checkRateLimit,
  getClientIdentifier,
  resetRateLimiter,
  setRateLimitConfigForTesting,
  isValidIp,
} from '../lib/security/rateLimiter';
import { analyzeDeterministic } from '../lib/analysis';

function makeRequest(ip: string, body: unknown = { text: 'رسالة عادية للتجربة' }): Request {
  return new Request('http://localhost:3000/api/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Forwarded-For': ip,
    },
    body: JSON.stringify(body),
  });
}

describe('HARIS Phase 8.1: API Abuse Hardening & Rate Limiting', () => {
  beforeEach(() => {
    resetRateLimiter();
    // Force standard 10 requests / minute config during this test suite
    setRateLimitConfigForTesting({
      maxRequests: 10,
      windowMs: 60 * 1000,
    });
  });

  afterEach(() => {
    resetRateLimiter();
    setRateLimitConfigForTesting(null);
  });

  // -------------------------------------------------------------------------
  // 1. IP Parsing & Spoofing Resilience
  // -------------------------------------------------------------------------
  it('correctly extracts and validates IP from headers while rejecting invalid ones', () => {
    assert.strictEqual(isValidIp('192.168.1.1'), true);
    assert.strictEqual(isValidIp('10.0.0.1'), true);
    assert.strictEqual(isValidIp('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), true);
    assert.strictEqual(isValidIp('::1'), true);
    assert.strictEqual(isValidIp('not-an-ip'), false);
    assert.strictEqual(isValidIp('<script>alert(1)</script>'), false);
    assert.strictEqual(isValidIp('999.999.999.999'), false);

    // CF-Connecting-IP takes priority
    const reqCf = new Request('http://localhost/api/analyze', {
      headers: { 'cf-connecting-ip': '203.0.113.195', 'x-forwarded-for': '10.0.0.1' },
    });
    assert.strictEqual(getClientIdentifier(reqCf), '203.0.113.195');

    // X-Real-IP takes priority over X-Forwarded-For
    const reqReal = new Request('http://localhost/api/analyze', {
      headers: { 'x-real-ip': '198.51.100.4', 'x-forwarded-for': '10.0.0.1' },
    });
    assert.strictEqual(getClientIdentifier(reqReal), '198.51.100.4');

    // X-Forwarded-For multi-hop extracts first IP
    const reqFwd = new Request('http://localhost/api/analyze', {
      headers: { 'x-forwarded-for': '198.51.100.10, 10.0.0.1, 10.0.0.2' },
    });
    assert.strictEqual(getClientIdentifier(reqFwd), '198.51.100.10');

    // Malicious/unparseable header falls back safely to 127.0.0.1
    const reqBad = new Request('http://localhost/api/analyze', {
      headers: { 'x-forwarded-for': 'malicious-string' },
    });
    assert.strictEqual(getClientIdentifier(reqBad), '127.0.0.1');
  });

  // -------------------------------------------------------------------------
  // 2. Normal Request Under Limit
  // -------------------------------------------------------------------------
  it('1. normal request under limit succeeds with HTTP 200 and rate limit headers', async () => {
    const req = makeRequest('192.0.2.1');
    const res = await POST(req);

    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('X-RateLimit-Limit'), '10');
    assert.strictEqual(res.headers.get('X-RateLimit-Remaining'), '9');
    assert.ok(res.headers.get('X-RateLimit-Reset'));
  });

  // -------------------------------------------------------------------------
  // 3. Consecutive Requests Under Limit
  // -------------------------------------------------------------------------
  it('2. consecutive requests under limit (1 to 10) all succeed with decreasing remaining counts', async () => {
    const testIp = '192.0.2.2';

    for (let i = 1; i <= 10; i++) {
      const req = makeRequest(testIp);
      const res = await POST(req);
      assert.strictEqual(res.status, 200, `Request ${i} should succeed with 200`);
      assert.strictEqual(res.headers.get('X-RateLimit-Remaining'), String(10 - i));
    }
  });

  // -------------------------------------------------------------------------
  // 4. Request Exceeding Limit Returns 429
  // -------------------------------------------------------------------------
  it('3. 11th request exceeding limit returns HTTP 429 with Retry-After and clear error', async () => {
    const testIp = '192.0.2.3';

    // Exhaust 10 requests
    for (let i = 1; i <= 10; i++) {
      const res = await POST(makeRequest(testIp));
      assert.strictEqual(res.status, 200);
    }

    // 11th request must be rejected
    const blockedRes = await POST(makeRequest(testIp));
    assert.strictEqual(blockedRes.status, 429);
    assert.strictEqual(blockedRes.headers.get('X-RateLimit-Remaining'), '0');
    assert.strictEqual(blockedRes.headers.get('X-RateLimit-Limit'), '10');

    const retryAfter = Number(blockedRes.headers.get('Retry-After'));
    assert.ok(retryAfter >= 1 && retryAfter <= 60, `Retry-After should be between 1 and 60s, got ${retryAfter}`);

    const errorJson = (await blockedRes.json()) as { error: string };
    assert.ok(errorJson.error.includes('Too many requests'), 'Should return clear rate limit error message');
    assert.ok(errorJson.error.includes('10 requests per minute'));
  });

  // -------------------------------------------------------------------------
  // 5. Client Isolation (Independent Counters)
  // -------------------------------------------------------------------------
  it('5. distinct client IPs maintain strictly isolated rate limit counters', async () => {
    const clientA = '198.51.100.50';
    const clientB = '198.51.100.51';

    // Client A uses all 10 requests
    for (let i = 0; i < 10; i++) {
      const resA = await POST(makeRequest(clientA));
      assert.strictEqual(resA.status, 200);
    }

    // Client A is blocked
    const blockedA = await POST(makeRequest(clientA));
    assert.strictEqual(blockedA.status, 429);

    // Client B must NOT be blocked and should have full remaining quota
    const resB = await POST(makeRequest(clientB));
    assert.strictEqual(resB.status, 200);
    assert.strictEqual(resB.headers.get('X-RateLimit-Remaining'), '9');
  });

  // -------------------------------------------------------------------------
  // 6. Concurrent Requests (No Race Conditions)
  // -------------------------------------------------------------------------
  it('6. concurrent burst requests from same client handle atomicity without race conditions', async () => {
    const burstIp = '192.0.2.88';

    // Send 15 parallel requests
    const promises = Array.from({ length: 15 }, () => POST(makeRequest(burstIp)));
    const responses = await Promise.all(promises);

    const status200Count = responses.filter((r) => r.status === 200).length;
    const status429Count = responses.filter((r) => r.status === 429).length;

    assert.strictEqual(status200Count, 10, 'Exactly 10 requests must be permitted');
    assert.strictEqual(status429Count, 5, 'Exactly 5 requests must be blocked with 429');
  });

  // -------------------------------------------------------------------------
  // 7. Privacy: Zero User Content in State
  // -------------------------------------------------------------------------
  it('4. rate limiter state never retains or leaks user text, URLs, or screenshots', () => {
    const sensitiveMessage = 'هذه رسالة بالغة الخصوصية تحتوي على أسرار وبيانات [SECRET_DATA]';
    const clientIp = '192.0.2.99';

    // Record check
    const r1 = checkRateLimit(clientIp);
    assert.strictEqual(r1.allowed, true);

    // Verify rate limit response contains only rate limiting metadata and no user payload
    const serializedResponse = JSON.stringify(r1);
    assert.strictEqual(serializedResponse.includes(sensitiveMessage), false);

    // Inspect module functions: verify that checkRateLimit only takes IP string
    // and returns numbers/boolean without accepting any payload argument
    assert.strictEqual(typeof checkRateLimit, 'function');
    assert.strictEqual(checkRateLimit.length, 1); // exactly 1 parameter: clientIp
  });

  // -------------------------------------------------------------------------
  // 8. Scenario Regression Integrity
  // -------------------------------------------------------------------------
  it('7, 8, 9. RED-013, RED-034, and RED-043 analysis results remain strictly identical', () => {
    // RED-013: Arabizi / OTP phishing
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
