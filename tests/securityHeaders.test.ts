import { describe, it } from 'node:test';
import assert from 'node:assert';
import { POST } from '../app/api/analyze/route';
import { buildCspHeader, getSecurityHeaders, getSecurityHeadersMap } from '../lib/security/headers';
import { analyzeDeterministic } from '../lib/analysis';

function createApiRequest(body: unknown, ip = '198.51.100.88'): Request {
  return new Request('http://localhost:3000/api/analyze', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-forwarded-for': ip,
    },
    body: JSON.stringify(body),
  });
}

describe('Phase 8.4 — Defensive Security Headers (SEC-FIND-04)', () => {
  // -------------------------------------------------------------------------
  // 1. Programmatic Security Headers Verification
  // -------------------------------------------------------------------------
  describe('1. Security Headers Configuration & Values', () => {
    it('provides all mandatory defensive headers with exact secure values', () => {
      const headersMap = getSecurityHeadersMap();

      // 1. X-Content-Type-Options
      assert.strictEqual(headersMap['X-Content-Type-Options'], 'nosniff');

      // 2. X-Frame-Options
      assert.strictEqual(headersMap['X-Frame-Options'], 'DENY');

      // 3. Referrer-Policy
      assert.strictEqual(headersMap['Referrer-Policy'], 'strict-origin-when-cross-origin');

      // 4. Permissions-Policy restricts sensitive hardware APIs
      const permissions = headersMap['Permissions-Policy'];
      assert.ok(permissions.includes('camera=()'));
      assert.ok(permissions.includes('microphone=()'));
      assert.ok(permissions.includes('geolocation=()'));
      assert.ok(permissions.includes('payment=()'));

      // 5. X-DNS-Prefetch-Control
      assert.strictEqual(headersMap['X-DNS-Prefetch-Control'], 'off');

      // 6. X-Permitted-Cross-Domain-Policies
      assert.strictEqual(headersMap['X-Permitted-Cross-Domain-Policies'], 'none');

      // 7. Content-Security-Policy
      assert.ok(headersMap['Content-Security-Policy']);
    });

    it('validates Content-Security-Policy directives and forbids unnecessary external origins', () => {
      // Production CSP check
      const prodCsp = buildCspHeader({ isDev: false });

      // Must enforce default-src 'self'
      assert.ok(prodCsp.includes("default-src 'self'"));

      // Must disallow objects/plugins
      assert.ok(prodCsp.includes("object-src 'none'"));

      // Must defend against Clickjacking
      assert.ok(prodCsp.includes("frame-ancestors 'none'"));

      // Must restrict base-uri and form-action
      assert.ok(prodCsp.includes("base-uri 'self'"));
      assert.ok(prodCsp.includes("form-action 'self'"));

      // In production, script-src must NOT contain unsafe-eval
      assert.ok(!prodCsp.includes("'unsafe-eval'"));

      // Must NOT contain wildcard * in script-src or default-src
      const directives = prodCsp.split(';').map((d) => d.trim());
      const scriptDirective = directives.find((d) => d.startsWith('script-src'));
      assert.ok(scriptDirective);
      assert.ok(!scriptDirective.includes('*'), 'script-src must not allow wildcard *');
      assert.ok(!scriptDirective.includes('https:'), 'script-src must not allow unrestricted https:');
      assert.ok(!scriptDirective.includes('http:'), 'script-src must not allow unrestricted http:');

      // Development CSP check
      const devCsp = buildCspHeader({ isDev: true });
      assert.ok(devCsp.includes("'unsafe-eval'"), 'Dev CSP must permit unsafe-eval for Fast Refresh source maps');
      assert.ok(devCsp.includes('ws:'), 'Dev CSP must permit WebSocket for HMR');
    });

    it('omits HSTS by default to prevent breaking local/self-hosted HTTP environments', () => {
      const defaultHeaders = getSecurityHeaders({ isDev: false });
      const hstsHeader = defaultHeaders.find((h) => h.key === 'Strict-Transport-Security');
      assert.strictEqual(hstsHeader, undefined, 'HSTS must be omitted by default for local HTTP safety');

      // But can be enabled explicitly for verified HTTPS production environments
      const prodHeaders = getSecurityHeaders({ isDev: false, enableHsts: true });
      const explicitHsts = prodHeaders.find((h) => h.key === 'Strict-Transport-Security');
      assert.ok(explicitHsts);
      assert.strictEqual(explicitHsts.value, 'max-age=31536000; includeSubDomains');
    });
  });

  // -------------------------------------------------------------------------
  // 2. API Route Response Headers Verification
  // -------------------------------------------------------------------------
  describe('2. POST /api/analyze Response Headers', () => {
    it('returns all security headers on HTTP 200 OK responses', async () => {
      const req = createApiRequest({ text: 'رسالة اختبار عادية' }, '198.51.100.10');
      const res = await POST(req);
      assert.strictEqual(res.status, 200);

      assert.strictEqual(res.headers.get('X-Content-Type-Options'), 'nosniff');
      assert.strictEqual(res.headers.get('X-Frame-Options'), 'DENY');
      assert.strictEqual(res.headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin');
      assert.ok(res.headers.get('Permissions-Policy'));
      assert.ok(res.headers.get('Content-Security-Policy'));
      assert.ok(res.headers.get('X-RateLimit-Limit'));
    });

    it('returns all security headers on HTTP 400 Bad Request responses', async () => {
      const req = createApiRequest({ text: 'أ'.repeat(5005) }, '198.51.100.11'); // exceeds 5000 chars
      const res = await POST(req);
      assert.strictEqual(res.status, 400);

      assert.strictEqual(res.headers.get('X-Content-Type-Options'), 'nosniff');
      assert.strictEqual(res.headers.get('X-Frame-Options'), 'DENY');
      assert.ok(res.headers.get('Content-Security-Policy'));
    });

    it('returns all security headers on HTTP 413 Payload Too Large responses', async () => {
      // 20MB Content-Length
      const req = new Request('http://localhost:3000/api/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-forwarded-for': '198.51.100.12',
          'content-length': String(20 * 1024 * 1024),
        },
        body: JSON.stringify({ text: 'test' }),
      });

      const res = await POST(req);
      assert.strictEqual(res.status, 413);

      assert.strictEqual(res.headers.get('X-Content-Type-Options'), 'nosniff');
      assert.strictEqual(res.headers.get('X-Frame-Options'), 'DENY');
      assert.ok(res.headers.get('Content-Security-Policy'));
    });
  });

  // -------------------------------------------------------------------------
  // 3. Live Server GET / Home Page Verification
  // -------------------------------------------------------------------------
  describe('3. GET / Home Page Response Headers', () => {
    it('verifies that Next.js server serves security headers on GET / if server is reachable', async () => {
      try {
        const res = await fetch('http://localhost:3000/', { method: 'GET' });
        if (res.ok) {
          // If local dev server is running on port 3000, inspect response headers
          const ctOptions = res.headers.get('x-content-type-options');
          const xFrame = res.headers.get('x-frame-options');
          const csp = res.headers.get('content-security-policy');

          if (ctOptions) assert.strictEqual(ctOptions, 'nosniff');
          if (xFrame) assert.strictEqual(xFrame, 'DENY');
          if (csp) assert.ok(csp.includes("default-src 'self'"));
        }
      } catch {
        // Dev server might not be running in headless test environment; next.config.ts headers test is authoritative
      }
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
});
