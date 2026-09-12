/**
 * HARIS (حارس) — Deterministic Passive URL Analyzer
 *
 * CRITICAL SECURITY PRINCIPLE:
 * - NO NETWORK FETCHING.
 * - NO REDIRECT FOLLOWING.
 * - NO OUTBOUND REQUESTS.
 * - Purely local lexical, structural, and cryptographic anomaly analysis.
 */

import { parse as parseDomain } from 'tldts';
import { ExtractedSignal } from './taxonomy';

export interface UrlAnalysisResult {
  rawUrl: string;
  normalizedUrl: string;
  isValid: boolean;
  protocol: string;
  hostname: string;
  port: string | null;
  path: string;
  hasQuery: boolean;
  queryParamCount: number;

  registrableDomain: string | null;
  publicSuffix: string | null;
  subdomain: string | null;
  subdomainCount: number;

  isIpHost: boolean;
  isPunycode: boolean;
  isSuspiciousTld: boolean;
  isUrlShortener: boolean;
  isHttpOnly: boolean;
  isNonStandardPort: boolean;
  hasDeepSubdomains: boolean;

  brandSpoofing: {
    detected: boolean;
    brandName?: string;
    isOfficialDomain: boolean;
    location: 'subdomain' | 'domain' | 'path' | 'none';
    detail?: string;
  };

  anomalies: string[];
  signals: ExtractedSignal[];
}

/**
 * List of TLDs heavily abused in automated phishing kits and scam campaigns
 */
const SUSPICIOUS_TLDS = new Set([
  'xyz',
  'top',
  'live',
  'buzz',
  'cc',
  'cfd',
  'click',
  'tk',
  'work',
  'ml',
  'ga',
  'gq',
  'cf',
  'site',
  'vip',
  'icu',
  'quest',
  'monster',
  'rest',
  'online',
  'cam',
  'fit',
  'beauty',
  'sbs',
]);

/**
 * Common URL Shortener services
 */
const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  'is.gd',
  't.co',
  'cutt.ly',
  'rebrand.ly',
  'ow.ly',
  'rb.gy',
  'shorturl.at',
  'v.gd',
  'soo.gd',
]);

/**
 * Target Brands commonly spoofed in Arabic-speaking regions and their legitimate domains
 */
interface BrandDefinition {
  brandKey: string;
  canonicalNameAr: string;
  keywords: string[];
  legitimateDomains: string[];
}

const TARGET_BRANDS: BrandDefinition[] = [
  {
    brandKey: 'alrajhi',
    canonicalNameAr: 'مصرف الراجحي',
    keywords: ['alrajhi', 'alrajhibank', 'elrajhi', 'rajhibank', 'الراجحي'],
    legitimateDomains: ['alrajhibank.com.sa', 'alrajhibank.com', 'alrajhicapital.com'],
  },
  {
    brandKey: 'alahli_snb',
    canonicalNameAr: 'البنك الأهلي السعودي (SNB)',
    keywords: ['alahli', 'alahlionline', 'snb', 'snbcapital', 'الأهلي'],
    legitimateDomains: ['alahli.com', 'snb.com.sa', 'alahlionline.com'],
  },
  {
    brandKey: 'riyad_bank',
    canonicalNameAr: 'بنك الرياض',
    keywords: ['riyadbank', 'riyad-bank', 'بنك الرياض'],
    legitimateDomains: ['riyadbank.com'],
  },
  {
    brandKey: 'alinma',
    canonicalNameAr: 'مصرف الإنماء',
    keywords: ['alinma', 'alinmabank', 'الإنماء'],
    legitimateDomains: ['alinma.com'],
  },
  {
    brandKey: 'absher',
    canonicalNameAr: 'منصة أبشر',
    keywords: ['absher', 'abshir', 'أبشر'],
    legitimateDomains: ['absher.sa', 'moi.gov.sa'],
  },
  {
    brandKey: 'zatca',
    canonicalNameAr: 'هيئة الزكاة والضريبة والجمارك',
    keywords: ['zatca', 'gazt', 'zakat', 'الزكاة'],
    legitimateDomains: ['zatca.gov.sa'],
  },
  {
    brandKey: 'spl_post',
    canonicalNameAr: 'البريد السعودي (سبل)',
    keywords: ['spl', 'splonline', 'barid', 'saudipost', 'سبل'],
    legitimateDomains: ['splonline.com.sa', 'sp.com.sa'],
  },
  {
    brandKey: 'aramex',
    canonicalNameAr: 'أرامكس',
    keywords: ['aramex', 'أرامكس'],
    legitimateDomains: ['aramex.com'],
  },
  {
    brandKey: 'dhl',
    canonicalNameAr: 'دي إتش إل (DHL)',
    keywords: ['dhl', 'dhl-express'],
    legitimateDomains: ['dhl.com', 'dhl.com.sa'],
  },
  {
    brandKey: 'smsa',
    canonicalNameAr: 'سمسا إكسبريس',
    keywords: ['smsa', 'smsaexpress'],
    legitimateDomains: ['smsaexpress.com'],
  },
  {
    brandKey: 'stc',
    canonicalNameAr: 'شركة الاتصالات (stc)',
    keywords: ['stc', 'stcpay'],
    legitimateDomains: ['stc.com.sa', 'stc.com', 'stcpay.com.sa'],
  },
];

/**
 * Suspicious security/banking keywords that appear in phishing subdomains
 */
const SUSPICIOUS_SUBDOMAIN_KEYWORDS = [
  'login',
  'signin',
  'secure',
  'security',
  'verify',
  'verification',
  'update',
  'account',
  'banking',
  'online',
  'portal',
  'auth',
  'claim',
  'otp',
  'renew',
];

/**
 * Check if hostname is an IPv4 or IPv6 address
 */
function checkIsIp(hostname: string): boolean {
  // IPv4 regex
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(hostname)) return true;

  // IPv6 check
  if (hostname.startsWith('[') && hostname.endsWith(']')) return true;
  if (hostname.includes(':') && /^[0-9a-fA-F:]+$/.test(hostname)) return true;

  return false;
}

/**
 * Parse and analyze a URL string purely locally
 */
export function analyzeUrl(rawInput: string): UrlAnalysisResult {
  const rawUrl = (rawInput || '').trim();
  const anomalies: string[] = [];
  const signals: ExtractedSignal[] = [];

  // Ensure scheme exists for URL parser
  let normalizedUrl = rawUrl;
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = 'https://' + normalizedUrl;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalizedUrl);
  } catch {
    return {
      rawUrl,
      normalizedUrl,
      isValid: false,
      protocol: '',
      hostname: '',
      port: null,
      path: '',
      hasQuery: false,
      queryParamCount: 0,
      registrableDomain: null,
      publicSuffix: null,
      subdomain: null,
      subdomainCount: 0,
      isIpHost: false,
      isPunycode: false,
      isSuspiciousTld: false,
      isUrlShortener: false,
      isHttpOnly: false,
      isNonStandardPort: false,
      hasDeepSubdomains: false,
      brandSpoofing: { detected: false, isOfficialDomain: false, location: 'none' },
      anomalies: ['عنوان URL غير صالح أو مشوه بنوياً'],
      signals: [],
    };
  }

  const protocol = parsed.protocol.toLowerCase();
  const hostname = parsed.hostname.toLowerCase();
  const port = parsed.port || null;
  const path = parsed.pathname;
  const hasQuery = parsed.search.length > 1;
  const queryParamCount = hasQuery ? Array.from(parsed.searchParams.keys()).length : 0;

  // Parse domain hierarchy using tldts
  const domainInfo = parseDomain(normalizedUrl);
  const registrableDomain = domainInfo.domain?.toLowerCase() || null;
  const publicSuffix = domainInfo.publicSuffix?.toLowerCase() || null;
  const subdomain = domainInfo.subdomain?.toLowerCase() || null;

  const subdomainsList = subdomain ? subdomain.split('.').filter(Boolean) : [];
  const subdomainCount = subdomainsList.length;

  // 1. IP Host check
  const isIpHost = checkIsIp(hostname) || !!domainInfo.isIp;
  if (isIpHost) {
    anomalies.push('استخدام عنوان IP مباشر للمضيف بدلاً من اسم نطاق رسمي معتمد');
    signals.push({
      id: `url-ip-${Date.now()}`,
      featureId: 'suspicious_url',
      detected: true,
      severity: 'high',
      confidence: 'high',
      source: 'url',
      evidenceText: hostname,
      explanation: 'الرابط يستخدم عنوان بروتوكول الإنترنت (IP) مباشرة، وهو تكتيك شائع في صفحات التصيد المؤقتة.',
    });
  }

  // 2. Punycode / Homograph check
  const isPunycode = hostname.includes('xn--');
  if (isPunycode) {
    anomalies.push('النطاق يحتوي على ترميز Punycode (قد يشير إلى هجوم أحرف متشابهة Homograph Attack)');
    signals.push({
      id: `url-punycode-${Date.now()}`,
      featureId: 'suspicious_url',
      detected: true,
      severity: 'high',
      confidence: 'high',
      source: 'url',
      evidenceText: hostname,
      explanation: 'استخدام ترميز بونيكود (Punycode) لمحاكاة أحرف هجائية لأسماء بنوك أو مؤسسات معروفة.',
    });
  }

  // 3. Suspicious TLD check
  const isSuspiciousTld = publicSuffix ? SUSPICIOUS_TLDS.has(publicSuffix) : false;
  if (isSuspiciousTld && publicSuffix) {
    anomalies.push(`استخدام نطاق علوي تجاري رخيص ومشتبه به (.${publicSuffix})`);
    signals.push({
      id: `url-tld-${Date.now()}`,
      featureId: 'suspicious_url',
      detected: true,
      severity: 'medium',
      confidence: 'high',
      source: 'url',
      evidenceText: `.${publicSuffix}`,
      explanation: `النطاق العلوي (.${publicSuffix}) غير شائع للاستخدام المؤسسي ومصنف دولياً بارتفاع وتيرة حملات الاحتيال عبره.`,
    });
  }

  // 4. URL Shortener check
  const isUrlShortener = registrableDomain ? URL_SHORTENERS.has(registrableDomain) : false;
  if (isUrlShortener && registrableDomain) {
    anomalies.push(`خدمة تقصير روابط (${registrableDomain}) تخفي الوجهة الحقيقية للموقع`);
    signals.push({
      id: `url-shortener-${Date.now()}`,
      featureId: 'suspicious_url',
      detected: true,
      severity: 'medium',
      confidence: 'high',
      source: 'url',
      evidenceText: registrableDomain,
      explanation: 'الرابط يستخدم خدمة تقصير لإخفاء النطاق النهائي، مما يستوجب توخي الحذر الشديد وعدم إدخال أي بيانات.',
    });
  }

  // 5. Insecure HTTP check
  const isHttpOnly = protocol === 'http:';
  if (isHttpOnly) {
    anomalies.push('الرابط غير مشفر (HTTP بدلاً من HTTPS)');
  }

  // 6. Non-standard port check (e.g. :8080, :8443, :8888)
  const isNonStandardPort = port !== null && port !== '80' && port !== '443';
  if (isNonStandardPort) {
    anomalies.push(`استخدام منفذ اتصال غير قياسي (${port})`);
  }

  // 7. Deep Subdomain depth check (> 2 subdomains)
  const hasDeepSubdomains = subdomainCount >= 3;
  if (hasDeepSubdomains) {
    anomalies.push(`تعدد مفرط في النطاقات الفرعية (عمق ${subdomainCount})`);
  }

  // 8. Brand Impersonation Analysis (Subdomain vs Registrable Domain vs Path)
  let brandSpoofing = {
    detected: false,
    brandName: undefined as string | undefined,
    isOfficialDomain: false,
    location: 'none' as 'subdomain' | 'domain' | 'path' | 'none',
    detail: undefined as string | undefined,
  };

  for (const brand of TARGET_BRANDS) {
    const isOfficial = registrableDomain ? brand.legitimateDomains.includes(registrableDomain) : false;

    if (isOfficial) {
      brandSpoofing = {
        detected: false,
        brandName: brand.canonicalNameAr,
        isOfficialDomain: true,
        location: 'domain',
        detail: `النطاق (${registrableDomain}) يطابق النطاق الرسمي المعتمد لـ ${brand.canonicalNameAr}`,
      };
      break;
    }

    // Check if brand keywords appear in subdomains (Classic Spoofing: alrajhi.attacker.com)
    const brandInSubdomain = subdomainsList.some((sub) =>
      brand.keywords.some((k) => sub.toLowerCase().includes(k))
    );

    // Check if brand keywords appear in domain name without being official (e.g. alrajhi-secure.com)
    const domainWithoutSuffix = domainInfo.domainWithoutSuffix?.toLowerCase() || '';
    const brandInDomain = brand.keywords.some((k) => domainWithoutSuffix.includes(k));

    // Check if brand keywords appear in path (e.g. attacker.com/alrajhi)
    const pathLower = path.toLowerCase();
    const brandInPath = brand.keywords.some((k) => pathLower.includes(`/${k}`) || pathLower.includes(`${k}/`));

    if (brandInSubdomain) {
      const detail = `انتحال اسم ${brand.canonicalNameAr} في النطاق الفرعي (${subdomain}) بينما النطاق الفعلي المسجل هو (${registrableDomain})`;
      brandSpoofing = {
        detected: true,
        brandName: brand.canonicalNameAr,
        isOfficialDomain: false,
        location: 'subdomain',
        detail,
      };
      anomalies.push(detail);
      signals.push({
        id: `url-spoof-subdomain-${Date.now()}`,
        featureId: 'impersonation',
        detected: true,
        severity: 'high',
        confidence: 'high',
        source: 'url',
        evidenceText: `${subdomain}.${registrableDomain}`,
        explanation: `محاولة خداع صريحة بوضع اسم ${brand.canonicalNameAr} في النطاق الفرعي لإيهام المستخدم بأنه الموقع الرسمي.`,
      });
      break;
    } else if (brandInDomain) {
      const detail = `استخدام اسم ${brand.canonicalNameAr} داخل نطاق غير معتمد (${registrableDomain})`;
      brandSpoofing = {
        detected: true,
        brandName: brand.canonicalNameAr,
        isOfficialDomain: false,
        location: 'domain',
        detail,
      };
      anomalies.push(detail);
      signals.push({
        id: `url-spoof-domain-${Date.now()}`,
        featureId: 'impersonation',
        detected: true,
        severity: 'high',
        confidence: 'high',
        source: 'url',
        evidenceText: registrableDomain || hostname,
        explanation: `النطاق (${registrableDomain}) يحاكي اسم ${brand.canonicalNameAr} ولكنه ليس النطاق الرسمي المسجل للجهة.`,
      });
      break;
    } else if (brandInPath) {
      // Brand in path of an arbitrary domain
      const detail = `وجود اسم ${brand.canonicalNameAr} في مسار رابط يعود لنطاق خارجي (${registrableDomain})`;
      brandSpoofing = {
        detected: true,
        brandName: brand.canonicalNameAr,
        isOfficialDomain: false,
        location: 'path',
        detail,
      };
      anomalies.push(detail);
      signals.push({
        id: `url-spoof-path-${Date.now()}`,
        featureId: 'impersonation',
        detected: true,
        severity: 'medium',
        confidence: 'medium',
        source: 'url',
        evidenceText: `${registrableDomain}${path}`,
        explanation: `الرابط يضع اسم ${brand.canonicalNameAr} في المسار ولكن النطاق الفعلي (${registrableDomain}) لا يتبع لهذه الجهة.`,
      });
      break;
    }
  }

  // 9. Phishing Keywords in Hostname (login, verify, secure, etc.)
  if (subdomain) {
    const hasPhishKeyword = SUSPICIOUS_SUBDOMAIN_KEYWORDS.some((kw) => subdomain.includes(kw));
    if (hasPhishKeyword && !brandSpoofing.isOfficialDomain) {
      anomalies.push(`النطاق الفرعي يحتوي على كلمات تصيد مضللة (${subdomain})`);
    }
  }

  return {
    rawUrl,
    normalizedUrl,
    isValid: true,
    protocol,
    hostname,
    port,
    path,
    hasQuery,
    queryParamCount,
    registrableDomain,
    publicSuffix,
    subdomain,
    subdomainCount,
    isIpHost,
    isPunycode,
    isSuspiciousTld,
    isUrlShortener,
    isHttpOnly,
    isNonStandardPort,
    hasDeepSubdomains,
    brandSpoofing,
    anomalies,
    signals,
  };
}
