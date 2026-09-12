import { describe, it } from 'node:test';
import assert from 'node:assert';
import { analyzeUrl } from '../lib/analysis/urlAnalyzer';

describe('Passive URL Analyzer Tests', () => {
  it('should identify a normal legitimate domain without spoofing', () => {
    const res = analyzeUrl('https://alrajhibank.com.sa/personal');
    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.registrableDomain, 'alrajhibank.com.sa');
    assert.strictEqual(res.brandSpoofing.isOfficialDomain, true);
    assert.strictEqual(res.brandSpoofing.detected, false);
    assert.strictEqual(res.isSuspiciousTld, false);
    assert.strictEqual(res.isIpHost, false);
  });

  it('should detect raw IP hosts', () => {
    const res = analyzeUrl('http://192.168.1.50/login.php');
    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.isIpHost, true);
    assert.strictEqual(res.signals.some((s) => s.featureId === 'suspicious_url'), true);
  });

  it('should detect Punycode homograph indicators', () => {
    const res = analyzeUrl('https://xn--alrajh-1xa.com/banking');
    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.isPunycode, true);
    assert.strictEqual(res.signals.some((s) => s.featureId === 'suspicious_url'), true);
  });

  it('should detect suspicious high-risk TLDs', () => {
    const res = analyzeUrl('https://secure-update-portal.xyz/login');
    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.isSuspiciousTld, true);
    assert.strictEqual(res.publicSuffix, 'xyz');
    assert.strictEqual(res.signals.some((s) => s.featureId === 'suspicious_url'), true);
  });

  it('should detect subdomain brand spoofing (e.g. alrajhi.secure-login.xyz)', () => {
    const res = analyzeUrl('https://alrajhi.secure-login.xyz/verify');
    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.registrableDomain, 'secure-login.xyz');
    assert.strictEqual(res.brandSpoofing.detected, true);
    assert.strictEqual(res.brandSpoofing.location, 'subdomain');
    assert.strictEqual(res.brandSpoofing.isOfficialDomain, false);
    assert.strictEqual(res.signals.some((s) => s.featureId === 'impersonation'), true);
  });

  it('should detect known URL shortener services', () => {
    const res = analyzeUrl('https://bit.ly/3xXyZ9');
    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.isUrlShortener, true);
    assert.strictEqual(res.signals.some((s) => s.featureId === 'suspicious_url'), true);
  });

  it('should detect deep subdomain nesting anomalies', () => {
    const res = analyzeUrl('https://login.service.verify.portal.malicious.com');
    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.hasDeepSubdomains, true);
    assert.ok(res.subdomainCount >= 3);
  });

  it('should distinguish normal path containing brand keyword on arbitrary domain', () => {
    const res = analyzeUrl('https://general-news-portal.com/business/articles/alrajhi-expansion');
    assert.strictEqual(res.isValid, true);
    assert.strictEqual(res.brandSpoofing.location, 'path');
    assert.strictEqual(res.hasDeepSubdomains, false);
    assert.strictEqual(res.isSuspiciousTld, false);
  });

  it('should handle malformed URL gracefully without throwing', () => {
    const res = analyzeUrl('not-a-valid-url-%%%%');
    assert.strictEqual(res.isValid, false);
    assert.ok(res.anomalies.length > 0);
  });
});
