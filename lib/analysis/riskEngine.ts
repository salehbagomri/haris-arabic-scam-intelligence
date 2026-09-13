/**
 * HARIS (حارس) — Deterministic Risk Engine & Evidence Synthesizer
 *
 * Combines deterministic signals, URL technical analysis, and configurable weights
 * into an explainable, transparent "درجة الاشتباه" (0 - 100).
 *
 * CRITICAL RULE:
 * This score is an index of threat evidence and suspicion, NOT a mathematical probability.
 * No single feature alone can force the score to 100.
 */

import {
  FeatureKey,
  ScamType,
  ExtractedSignal,
  SCAM_TYPES_METADATA,
} from './taxonomy';
import { WeightsConfig, DEFAULT_RISK_WEIGHTS } from '../config/weights';
import { UrlAnalysisResult } from './urlAnalyzer';
import { EvidenceItem } from '../types/analysis';

export interface RiskAssessmentResult {
  /** "درجة الاشتباه" (0 - 100) — Heuristic suspicion score based on evidence */
  score: number;

  /** Risk level classification */
  level: 'low' | 'suspicious' | 'high';

  /** Classified scam type pattern */
  scamType: ScamType;

  /** Human-readable Arabic name of the scam type */
  scamTypeNameAr: string;

  /** Structured evidence items with severity and classification */
  evidence: EvidenceItem[];

  /** All detected threat feature keys */
  detectedFeatures: FeatureKey[];

  /** Feature-level evidence mapping (Scam DNA evidence grounding) */
  featureEvidence: Record<FeatureKey, ExtractedSignal[]>;

  /** Concise executive security summary */
  summary: string;

  /** Actionable, context-tailored safety advice */
  actionableAdvice: string[];

  /** Transparent uncertainties and analytical limitations */
  uncertainties: string[];

  /** Aggregated URL findings across all analyzed URLs */
  urlFindings?: {
    totalUrls: number;
    suspiciousUrlsCount: number;
    urls: Array<{
      url: string;
      hostname: string;
      isSuspicious: boolean;
      anomalies: string[];
      signals: ExtractedSignal[];
    }>;
  };
}

/**
 * Classify the most probable Scam Type from the set of detected signals and all analyzed URLs
 */
export function classifyScamType(
  detectedFeatures: FeatureKey[],
  evidenceTexts: string[],
  urlAnalyses?: UrlAnalysisResult | UrlAnalysisResult[]
): ScamType {
  const urlsList: UrlAnalysisResult[] = Array.isArray(urlAnalyses)
    ? urlAnalyses
    : urlAnalyses
    ? [urlAnalyses]
    : [];

  const hasAnyAnomalies = urlsList.some((u) => u.anomalies.length > 0);
  if (detectedFeatures.length === 0 && !hasAnyAnomalies) {
    return 'UNKNOWN';
  }

  const combinedEvidence = evidenceTexts.join(' ').toLowerCase();

  // 0. Specific Account / Wallet Takeover Check (takes precedence when explicit OTP or credential theft occurs under threat targeting wallet)
  if (
    (detectedFeatures.includes('otp_request') && detectedFeatures.includes('secrecy_pressure')) ||
    (detectedFeatures.includes('threat_language') &&
      (detectedFeatures.includes('credential_request') || detectedFeatures.includes('otp_request')) &&
      combinedEvidence.includes('محفظ'))
  ) {
    return 'ACCOUNT_TAKEOVER';
  }

  // Use URL brand spoofing signals if present from ANY analyzed URL
  for (const u of urlsList) {
    if (u.brandSpoofing.detected) {
      const brand = u.brandSpoofing.brandName || '';
      if (brand.includes('البريد') || brand.includes('أرامكس') || brand.includes('DHL')) {
        return 'DELIVERY_SCAM';
      }
      if (
        brand.includes('الراجحي') ||
        brand.includes('الأهلي') ||
        brand.includes('الرياض') ||
        brand.includes('الإنماء') ||
        brand.includes('مصرف') ||
        brand.includes('بنك')
      ) {
        return 'BANK_IMPERSONATION';
      }
      if (brand.includes('أبشر') || brand.includes('الزكاة')) {
        return 'GOVERNMENT_IMPERSONATION';
      }
    }
  }

  // 1. Government Impersonation
  if (
    detectedFeatures.includes('impersonation') &&
    (combinedEvidence.includes('ابشر') ||
      combinedEvidence.includes('زكاه') ||
      combinedEvidence.includes('قضاء') ||
      combinedEvidence.includes('قضائ') ||
      combinedEvidence.includes('قبض') ||
      combinedEvidence.includes('وزاره') ||
      combinedEvidence.includes('هيئ') ||
      combinedEvidence.includes('منصه'))
  ) {
    return 'GOVERNMENT_IMPERSONATION';
  }

  // 1b. Delivery Scam Check
  if (
    detectedFeatures.includes('suspicious_payment_request') &&
    (combinedEvidence.includes('شحن') ||
      combinedEvidence.includes('طرد') ||
      combinedEvidence.includes('سبل') ||
      combinedEvidence.includes('ارامكس') ||
      combinedEvidence.includes('delivery'))
  ) {
    return 'DELIVERY_SCAM';
  }

  // 1c. Payment Scam Check
  if (
    detectedFeatures.includes('suspicious_payment_request') &&
    (combinedEvidence.includes('حواله') ||
      combinedEvidence.includes('تحويل') ||
      combinedEvidence.includes('رسوم') ||
      combinedEvidence.includes('سداد') ||
      combinedEvidence.includes('دفع') ||
      combinedEvidence.includes('غرام'))
  ) {
    return 'PAYMENT_SCAM';
  }

  // 2. Bank Impersonation Check
  if (
    (detectedFeatures.includes('impersonation') || detectedFeatures.includes('threat_language')) &&
    (detectedFeatures.includes('credential_request') || detectedFeatures.includes('otp_request'))
  ) {
    if (
      combinedEvidence.includes('بنك') ||
      combinedEvidence.includes('مصرف') ||
      combinedEvidence.includes('بطاق') ||
      combinedEvidence.includes('حساب') ||
      combinedEvidence.includes('الراجحي') ||
      combinedEvidence.includes('الاهلي') ||
      combinedEvidence.includes('bank') ||
      combinedEvidence.includes('7sab') ||
      combinedEvidence.includes('كريمي') ||
      combinedEvidence.includes('مدى')
    ) {
      return 'BANK_IMPERSONATION';
    }
  }

  // 3. Fake Prize / Lottery Check
  if (
    detectedFeatures.includes('financial_lure') &&
    (detectedFeatures.includes('action_pressure') ||
      detectedFeatures.includes('suspicious_url') ||
      detectedFeatures.includes('credential_request') ||
      detectedFeatures.includes('unexpected_contact') ||
      detectedFeatures.includes('impersonation'))
  ) {
    if (
      combinedEvidence.includes('مبروك') ||
      combinedEvidence.includes('جائز') ||
      combinedEvidence.includes('ربحت') ||
      combinedEvidence.includes('فزت') ||
      combinedEvidence.includes('كسبت') ||
      combinedEvidence.includes('قسيم') ||
      combinedEvidence.includes('mbroo') ||
      combinedEvidence.includes('mabroo') ||
      combinedEvidence.includes('fzt') ||
      combinedEvidence.includes('prize') ||
      combinedEvidence.includes('باق') ||
      combinedEvidence.includes('مجان') ||
      combinedEvidence.includes('منح') ||
      combinedEvidence.includes('شيك') ||
      combinedEvidence.includes('سحب') ||
      combinedEvidence.includes('gift') ||
      combinedEvidence.includes('claim')
    ) {
      return 'FAKE_PRIZE';
    }
  }

  // 4. Investment Scam Check
  if (
    detectedFeatures.includes('financial_lure') &&
    (combinedEvidence.includes('استثمار') ||
      combinedEvidence.includes('تداول') ||
      combinedEvidence.includes('ارباح') ||
      combinedEvidence.includes('دخل') ||
      combinedEvidence.includes('اضعاف') ||
      combinedEvidence.includes('مستثمر') ||
      combinedEvidence.includes('اسهم'))
  ) {
    return 'INVESTMENT_SCAM';
  }

  // 4b. Job Scam Check
  if (
    detectedFeatures.includes('financial_lure') &&
    (combinedEvidence.includes('وظيفة') ||
      combinedEvidence.includes('توظيف') ||
      combinedEvidence.includes('تجنيد') ||
      combinedEvidence.includes('تقييم') ||
      combinedEvidence.includes('عمل بسيط') ||
      combinedEvidence.includes('من المنزل') ||
      combinedEvidence.includes('راتب'))
  ) {
    return 'JOB_SCAM';
  }

  // 5. Account Takeover Check
  if (
    (detectedFeatures.includes('otp_request') && detectedFeatures.includes('secrecy_pressure')) ||
    (detectedFeatures.includes('otp_request') &&
      (combinedEvidence.includes('واتساب') ||
        combinedEvidence.includes('whatsapp') ||
        combinedEvidence.includes('تيليجرام') ||
        combinedEvidence.includes('telegram') ||
        combinedEvidence.includes('انستغرام') ||
        combinedEvidence.includes('instagram') ||
        combinedEvidence.includes('استرجع') ||
        combinedEvidence.includes('حسابي'))) ||
    (detectedFeatures.includes('credential_request') &&
      (combinedEvidence.includes('بريد') ||
        combinedEvidence.includes('حساب') ||
        combinedEvidence.includes('دخول') ||
        combinedEvidence.includes('صلاحية') ||
        combinedEvidence.includes('portal') ||
        combinedEvidence.includes('auth') ||
        combinedEvidence.includes('مرور')))
  ) {
    return 'ACCOUNT_TAKEOVER';
  }

  // 7. General scoring against metadata primaryFeatures
  let bestType: ScamType = 'UNKNOWN';
  let bestOverlapCount = 0;

  for (const [typeKey, meta] of Object.entries(SCAM_TYPES_METADATA)) {
    if (typeKey === 'UNKNOWN') continue;
    // Guard DELIVERY_SCAM: must have delivery context
    if (typeKey === 'DELIVERY_SCAM') {
      const hasDeliveryContext =
        combinedEvidence.includes('شحن') ||
        combinedEvidence.includes('طرد') ||
        combinedEvidence.includes('توصيل') ||
        combinedEvidence.includes('بريد') ||
        combinedEvidence.includes('سبل') ||
        combinedEvidence.includes('ارامكس') ||
        combinedEvidence.includes('dhl') ||
        combinedEvidence.includes('smsa') ||
        combinedEvidence.includes('delivery') ||
        combinedEvidence.includes('shipping') ||
        combinedEvidence.includes('package');
      if (!hasDeliveryContext) continue;
    }
    // Guard FAKE_PRIZE: must have financial_lure
    if (typeKey === 'FAKE_PRIZE' && !detectedFeatures.includes('financial_lure')) {
      continue;
    }
    const overlap = meta.primaryFeatures.filter((f) => detectedFeatures.includes(f)).length;
    if (overlap > bestOverlapCount) {
      bestOverlapCount = overlap;
      bestType = typeKey as ScamType;
    }
  }

  if (bestOverlapCount >= 2) {
    return bestType;
  }

  return detectedFeatures.length > 0 ? 'SOCIAL_ENGINEERING' : 'UNKNOWN';
}

/**
 * Generate targeted actionable advice based on detected threat features
 */
function generateActionableAdvice(
  detectedFeatures: FeatureKey[],
  scamType: ScamType,
  urlsList: UrlAnalysisResult[]
): string[] {
  const advice: string[] = [];

  const hasSuspiciousUrl =
    detectedFeatures.includes('suspicious_url') ||
    urlsList.some((u) => u.isSuspiciousTld || u.isIpHost || u.brandSpoofing.detected || u.isPunycode || u.isUrlShortener);

  if (hasSuspiciousUrl) {
    advice.push('لا تضغط على الرابط نهائياً، ولا تفتح أي صفحات يوجهك إليها.');
  }

  if (urlsList.length > 1) {
    const hasSuspicious = urlsList.some((u) => u.signals.length > 0 || u.brandSpoofing.detected);
    const hasBenign = urlsList.some((u) => u.signals.length === 0 && !u.brandSpoofing.detected);
    if (hasSuspicious && hasBenign) {
      advice.push('احذر من التمويه بالروابط: الرسالة تدمج روابط رسمية أو موثوقة مع روابط تصيد أخرى لتضليلك.');
    }
  }

  if (detectedFeatures.includes('otp_request')) {
    advice.push('لا تشارك رمز التحقق لمرة واحدة (OTP) أو كود المصادقة مع أي شخص تحت أي ظرف.');
  }

  if (detectedFeatures.includes('credential_request')) {
    advice.push('لا تدخل أرقام بطاقتك البنكية، رمز الأمان CVV، أو كلمة المرور في أي نموذج غير رسمي.');
  }

  if (scamType === 'BANK_IMPERSONATION' || detectedFeatures.includes('impersonation')) {
    advice.push('تواصل فوراً مع الجهة الرسمية عبر قنواتها المعتمدة أو الرقم المطبوع خلف بطاقتك المصرفية.');
  }

  if (scamType === 'DELIVERY_SCAM') {
    advice.push('افتح التطبيق الرسمي لشركة التوصيل برقم التتبع للتحقق من وجود أي شحنة مسجلة برقم هويتك.');
  }

  if (detectedFeatures.includes('threat_language')) {
    advice.push('تجاهل التهديد بوقف الحساب؛ البنوك والجهات الرسمية لا تجمد الحسابات عبر رسائل فورية عشوائية.');
  }

  // General fallback advice
  if (advice.length === 0) {
    advice.push('تحقق من هوية المرسل وقناة التواصل قبل مشاركة أي معلومات أو اتخاذ إجراء.');
    advice.push('إذا كان المحتوى يتعلق بتعامل مالي، استشر شخصاً موثوقاً أو اتصل بجهة الدعم الرسمية.');
  }

  advice.push('احظر جهة الاتصال المشبوهة وأبلغ عنها للجهات الرسمية لمكافحة الاحتيال.');
  return Array.from(new Set(advice));
}

/**
 * Compute the Risk Assessment
 */
export function calculateRiskScore(
  signals: ExtractedSignal[],
  urlAnalyses?: UrlAnalysisResult | UrlAnalysisResult[],
  config: WeightsConfig = DEFAULT_RISK_WEIGHTS
): RiskAssessmentResult {
  const urlsList: UrlAnalysisResult[] = Array.isArray(urlAnalyses)
    ? urlAnalyses
    : urlAnalyses
    ? [urlAnalyses]
    : [];

  const hasAnyAnomalies = urlsList.some((u) => u.anomalies.length > 0);

  // Initialize featureEvidence container
  const featureEvidence: Record<FeatureKey, ExtractedSignal[]> = {
    urgency: [],
    credential_request: [],
    otp_request: [],
    impersonation: [],
    financial_lure: [],
    suspicious_url: [],
    threat_language: [],
    unexpected_contact: [],
    secrecy_pressure: [],
    suspicious_payment_request: [],
    action_pressure: [],
  };

  // 1. If no signals at all, return safe baseline
  if (signals.length === 0 && !hasAnyAnomalies) {
    return {
      score: 0,
      level: 'low',
      scamType: 'UNKNOWN',
      scamTypeNameAr: 'محتوى اعتيادي / غير مصنف كاحتيال',
      evidence: [],
      detectedFeatures: [],
      featureEvidence,
      summary: 'لم يتم رصد مؤشرات احتيال أو روابط مشبوهة في المحتوى المفحوص.',
      actionableAdvice: ['المحتوى لا يظهر علامات احتيال ظاهرة، ولكن احرص دائماً على عدم مشاركة بياناتك الحساسة.'],
      uncertainties: ['الفحص استدلالي محلي يعتمد على القواعد المعلنة ولا يغطي السياقات غير المتاحة في النص.'],
      urlFindings: urlsList.length > 0 ? {
        totalUrls: urlsList.length,
        suspiciousUrlsCount: 0,
        urls: urlsList.map((u) => ({
          url: u.rawUrl,
          hostname: u.hostname,
          isSuspicious: false,
          anomalies: u.anomalies,
          signals: u.signals,
        })),
      } : undefined,
    };
  }

  // Populate featureEvidence with detected signals
  for (const sig of signals) {
    if (sig.detected && featureEvidence[sig.featureId]) {
      featureEvidence[sig.featureId].push(sig);
    }
  }

  // 2. Aggregate signals by feature to avoid duplicate weighting
  const featureScores: Record<FeatureKey, number> = {
    urgency: 0,
    credential_request: 0,
    otp_request: 0,
    impersonation: 0,
    financial_lure: 0,
    suspicious_url: 0,
    threat_language: 0,
    unexpected_contact: 0,
    secrecy_pressure: 0,
    suspicious_payment_request: 0,
    action_pressure: 0,
  };

  const evidenceItems: EvidenceItem[] = [];
  const evidenceTexts: string[] = [];

  for (const sig of signals) {
    if (!sig.detected) continue;

    evidenceTexts.push(sig.evidenceText);

    // Calculate individual signal score
    const baseWeight = config.featureWeights[sig.featureId] || 15;
    const confMultiplier = config.confidenceMultipliers[sig.confidence] || 0.75;
    const sevMultiplier = config.severityMultipliers[sig.severity] || 0.7;

    const signalScore = baseWeight * confMultiplier * sevMultiplier;

    // Take max score for this feature
    if (signalScore > featureScores[sig.featureId]) {
      featureScores[sig.featureId] = signalScore;
    }

    evidenceItems.push({
      id: sig.id,
      title: sig.explanation,
      description: `الدليل المرصود: "${sig.evidenceText}"`,
      severity: sig.severity,
      source: sig.source === 'url' ? 'technical' : sig.source === 'text' ? 'linguistic' : 'behavioral',
    });
  }

  // 3. Sum feature scores with individual contribution cap
  let rawScore = 0;
  const detectedFeatures: FeatureKey[] = [];

  for (const [feat, score] of Object.entries(featureScores)) {
    if (score > 0) {
      detectedFeatures.push(feat as FeatureKey);
      // Cap single feature contribution
      const cappedScore = Math.min(score, config.maxSingleFeatureContribution);
      rawScore += cappedScore;
    }
  }

  // 4. Multi-Feature Synergy Bonus (3+ correlated threat signals)
  const highThreatCount = detectedFeatures.filter((f) =>
    [
      'otp_request',
      'credential_request',
      'impersonation',
      'suspicious_url',
      'threat_language',
      'financial_lure',
      'suspicious_payment_request',
      'urgency',
    ].includes(f)
  ).length;

  if (highThreatCount >= 3) {
    rawScore *= config.synergyBonusMultiplier;
  }

  // 5. Final bounded score (0 - 100)
  const score = Math.min(100, Math.max(0, Math.round(rawScore)));

  // 6. Level classification
  let level: 'low' | 'suspicious' | 'high' = 'low';
  if (score >= config.thresholds.highMin) {
    level = 'high';
  } else if (score >= config.thresholds.lowMax + 1) {
    level = 'suspicious';
  }

  // 7. Classify Scam Type
  const scamType = classifyScamType(detectedFeatures, evidenceTexts, urlsList);
  const scamTypeMeta = SCAM_TYPES_METADATA[scamType];

  // 8. Generate Summary
  let summary = '';
  if (level === 'high') {
    summary = `رصد مؤشرات قوية ومتعددة لنمط (${scamTypeMeta.nameAr})؛ المحتوى يتضمن أساليب تلاعب وضغط تهدف لاستدراج بياناتك أو أموالك.`;
  } else if (level === 'suspicious') {
    summary = `رصد مؤشرات تتطلب الحذر لنمط (${scamTypeMeta.nameAr})؛ المحتوى يحمل شبهات أمنية غير مؤكدة قطعياً وينصح بعدم التجاوب معه.`;
  } else {
    summary = 'درجة الاشتباه منخفضة؛ المؤشرات الظاهرة لا تتضمن عناصر احتيال صريحة، مع ضرورة الحذر العام.';
  }

  // 9. Actionable Advice & Uncertainties
  const actionableAdvice = generateActionableAdvice(detectedFeatures, scamType, urlsList);

  const uncertainties: string[] = [
    'التقييم استدلالي محلي مبني على المؤشرات اللغوية والهندسية والتقنية المتاحة في النص/الرابط.',
    'حارس لا يقوم بالاتصال بالروابط المشبوهة أو فحص خوادمها الحية تأكيداً لسياسة الفحص السلبي الآمن.',
    'هذه النتيجة تعبر عن "درجة الاشتباه" وفق القواعد المرصودة ولا تمثل حكماً قضائياً أو قانونياً قاطعاً.',
  ];

  // 10. URL findings
  let urlFindings: RiskAssessmentResult['urlFindings'] = undefined;
  if (urlsList.length > 0) {
    const hasBenign = urlsList.some((u) => u.signals.length === 0 && !u.brandSpoofing.detected);

    urlFindings = {
      totalUrls: urlsList.length,
      suspiciousUrlsCount: urlsList.filter((u) => u.signals.length > 0 || u.brandSpoofing.detected).length,
      urls: urlsList.map((u) => {
        const isSuspicious = u.signals.length > 0 || u.brandSpoofing.detected;
        const anomalies = [...u.anomalies];
        if (urlsList.length > 1 && isSuspicious && hasBenign) {
          anomalies.push('رابط مشبوه مقترن برابط رسمي/موثوق (تمويه بروابط متعددة)');
        }
        return {
          url: u.rawUrl,
          hostname: u.hostname,
          isSuspicious,
          anomalies,
          signals: u.signals,
        };
      }),
    };
  }

  return {
    score,
    level,
    scamType,
    scamTypeNameAr: scamTypeMeta.nameAr,
    evidence: evidenceItems,
    detectedFeatures,
    featureEvidence,
    summary,
    actionableAdvice,
    uncertainties,
    urlFindings,
  };
}
