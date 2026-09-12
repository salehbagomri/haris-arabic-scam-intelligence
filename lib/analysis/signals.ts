/**
 * HARIS (حارس) — Deterministic Signal Extractor
 *
 * Implements intent-aware rule extraction for Scam DNA features without an LLM.
 *
 * CRITICAL RULE:
 * Avoid naive keyword matching! We rigorously inspect context to differentiate
 * between legitimate security warnings (e.g. "لا تشارك رمز التحقق") and actual
 * malicious requests (e.g. "أدخل رمز التحقق لتأكيد طلبك").
 */

import { FeatureKey, ExtractedSignal, Severity } from './taxonomy';
import { NormalizedTextResult } from './normalizer';
import { UrlAnalysisResult } from './urlAnalyzer';

export interface SignalExtractionResult {
  signals: ExtractedSignal[];
  hasCriticalThreat: boolean;
  detectedFeatures: FeatureKey[];
  linguisticAnomalies: string[];
}

interface PatternRule {
  id: string;
  featureId: FeatureKey;
  severity: Severity;
  /** Primary intent regexes indicating malicious or suspicious behavior */
  positivePatterns: RegExp[];
  /** Contextual negative regexes indicating legitimate warnings or benign contexts */
  negativePatterns?: RegExp[];
  explanation: string;
}

/**
 * Deterministic Signal Pattern Rules Matrix
 */
const DETERMINISTIC_RULES: PatternRule[] = [
  // 1. OTP Request (Intent-aware)
  {
    id: 'rule-otp-request',
    featureId: 'otp_request',
    severity: 'high',
    positivePatterns: [
      /(?:و)?(?:ادخل|ادخال|ارسل|ارسال|شارك|مشاركه|زودنا|اكتب|اعطني|ضع)\s+(?:بـ)?(?:رمز|كود|الرمز|الكود)\s+(?:التحقق|التاكيد|السري|المؤقت|otp|code)/i,
      /(?:رمز|كود)\s+(?:التحقق|التاكيد|otp)\s+(?:المرسل|الخاص بك|المطلوب|لتفعيل|لتاكيد|لتحديث)/i,
      /(?:enter|send|share|provide)\s+(?:your\s+)?(?:otp|verification\s+code|security\s+code)/i,
    ],
    negativePatterns: [
      /(?:لا\s+تشارك|احذر\s+من\s+مشاركة|لن\s+يطلب|لا\s+تعط|للحفاظ\s+على|تنبيه\s+امني|never\s+share|do\s+not\s+share|warns?\s+you)/i,
    ],
    explanation: 'طلب صريح لإدخال أو مشاركة رمز التحقق لمرة واحدة (OTP) المخصص للمصادقة وتأكيد العمليات.',
  },

  // 2. Credential Request (Intent-aware)
  {
    id: 'rule-credential-request',
    featureId: 'credential_request',
    severity: 'high',
    positivePatterns: [
      /(?:ادخل|حدث|اكتب|تسجيل|تاكيد)\s+(?:بيانات|معلومات)?\s*(?:كلمه\s+المرور|الرقم\s+السري|password|cvv|رقم\s+البطاقه|بيانات\s+الدخول)/i,
      /(?:يرجى\s+)?(?:تحديث|تاكيد|تنشيط)\s+(?:بياناتك|بيانات|معلوماتك|حسابك|بطاقتك)/i,
      /(?:enter|update|verify|confirm)\s+(?:your\s+)?(?:password|card\s+number|cvv|pin|credentials)/i,
      /(?:update|verify)\s+(?:your\s+)?account\s+details/i,
    ],
    negativePatterns: [
      /(?:غير\s+كلمه\s+المرور|للحفاظ\s+على\s+امان|تغيير\s+دوري|نصيحه\s+امنيه|لا\s+تدخل\s+بياناتك)/i,
    ],
    explanation: 'محاولة استدراج كلمات المرور أو أرقام البطاقة البنكية ورمز الحماية CVV.',
  },

  // 3. Urgency & Time Pressure
  {
    id: 'rule-urgency',
    featureId: 'urgency',
    severity: 'high',
    positivePatterns: [
      /(?:خلال|في\s+غضون)\s+(?:\d+|ساعه|ساعتين|24\s+ساعه|يوم|دقائق)/i,
      /(?:فورا|عاجل|بشكل\s+عاجل|حاليا|في\s+الحال|قبل\s+فوات\s+الانوان|اخر\s+فرصه|بسرعه)/i,
      /(?:immediately|urgent|within\s+\d+\s+(?:hours?|mins?|days?)|limited\s+time)/i,
    ],
    explanation: 'ممارسة ضغط زمني مصطنع لإرباك المستخدم ودفعه للاستجابة السريعة دون تدقيق.',
  },

  // 4. Threat & Intimidation Language
  {
    id: 'rule-threat-language',
    featureId: 'threat_language',
    severity: 'high',
    positivePatterns: [
      /(?:سيتم|سوف\s+يتم|تم)\s+(?:ايقاف|تجميد|حظر|تعليق|قفل|الغاء)(?:ه)?(?:\s+(?:حسابك|بطاقتك|خدماتك|شحنتك))?/i,
      /(?:حسابك\s+(?:راح|سوف|رح)?\s*(?:يتقفل|يتجمد|يوقف))/i,
      /(?:لتجنب\s+الغرامه|فرض\s+غرامه|مسائله\s+قانونيه|اجراء\s+قضائي|ايقاف\s+الخدمات)/i,
      /(?:account\s+(?:suspended|blocked|locked|terminated)|legal\s+action)/i,
    ],
    negativePatterns: [
      /(?:لحمايتك|لتفادي\s+الاحتيال|احذر|تحذير\s+من|تجنب\s+(?:الاحتيال|الروابط|المشاركه))/i,
    ],
    explanation: 'استخدام التهديد بتجميد الحساب أو فرض غرامات لإرهاب الضحية واستدراجها.',
  },

  // 5. Financial Lure & Fake Rewards
  {
    id: 'rule-financial-lure',
    featureId: 'financial_lure',
    severity: 'high',
    positivePatterns: [
      /(?:مبروك|تهانينا|ربحت|فزت|كسبت)\s+(?:معنا|بجائزه|مبلغ|سياره|قسيمه|هديه)/i,
      /(?:استثمار\s+مضمون|ارباح\s+يوميه|دخل\s+اضافي\s+مضمون|ثراء\s+سريع)/i,
      /(?:congratulations|you\s+won|won\s+(?:a\s+)?prize|guaranteed\s+returns?)/i,
    ],
    explanation: 'استدراج الضحية بإيهامها بالحصول على مبالغ مالية غير واقعية أو مكافآت وجوائز وهمية.',
  },

  // 6. Suspicious Payment Request (Delivery / Small fees)
  {
    id: 'rule-suspicious-payment',
    featureId: 'suspicious_payment_request',
    severity: 'high',
    positivePatterns: [
      /(?:سداد|دفع|تحويل)\s+(?:رسوم|مبلغ)\s+(?:شحن|جمارك|توصيل|معلقه|رمزي)/i,
      /(?:رسوم\s+(?:الشحن|التوصيل|الجمارك)\s*(?:المتبقيه|المعلقه)?\s*[:=]?\s*\d+)/i,
      /(?:pay|transfer|settle)\s+(?:delivery|customs|clearance|shipping)\s+fees?/i,
    ],
    explanation: 'المطالبة بسداد مبالغ رمزية أو رسوم شحن معلقة كذريعة للاستيلاء على بطاقات الدفع.',
  },

  // 7. Secrecy Pressure
  {
    id: 'rule-secrecy-pressure',
    featureId: 'secrecy_pressure',
    severity: 'high',
    positivePatterns: [
      /(?:لا\s+تخبر\s+احدا|سري\s+للغايه|بيننا\s+فقط|لا\s+تتحدث\s+مع|بشكل\s+سري)/i,
      /(?:keep\s+it\s+secret|do\s+not\s+tell\s+anyone|confidential\s+between\s+us)/i,
    ],
    explanation: 'مطالبة صريحة بالحفاظ على سرية المحادثة لعزل الضحية ومنعها من استشارة ذوي الخبرة.',
  },

  // 8. Action Pressure (Urgent CTA)
  {
    id: 'rule-action-pressure',
    featureId: 'action_pressure',
    severity: 'medium',
    positivePatterns: [
      /(?:اضغط\s+(?:على\s+)?الرابط|انقر\s+هنا|سارع\s+بالتسجيل|سارع\s+بالدخول|تابع\s+الرابط)/i,
      /(?:click\s+here|follow\s+link|visit\s+link\s+now)/i,
    ],
    explanation: 'حث ملح على النقر المباشر على الرابط لاتخاذ الإجراء المطلوب فوراً.',
  },
];

/**
 * Entity Keywords for Impersonation Detection in Text
 */
const IMPERSONATION_KEYWORDS = [
  { name: 'مصرف الراجحي', pattern: /(?:مصرف|بنك)?\s*الراجحي/i },
  { name: 'البنك الأهلي', pattern: /(?:البنك\s+الاهلي|snb|الاهلي\s+اونلاين)/i },
  { name: 'بنك الرياض', pattern: /بنك\s+الرياض/i },
  { name: 'أبشر', pattern: /(?:منصه|بوابه)?\s*ابشر/i },
  { name: 'البريد السعودي (سبل)', pattern: /(?:البريد\s+السعودي|سبل|شحنتك\s+رقم)/i },
  { name: 'أرامكس', pattern: /(?:ارامكس|aramex)/i },
  { name: 'دي إتش إل', pattern: /(?:دي\s+ايتش\s+ال|dhl)/i },
  { name: 'وزارة التجارة', pattern: /وزاره\s+التجاره/i },
  { name: 'الزكاة والضريبة', pattern: /(?:هيئه\s+الزكاه|زكاه\s+ودخل|zatca)/i },
];

/**
 * Extract signals from normalized text and URL analysis
 */
export function extractDeterministicSignals(
  normalized: NormalizedTextResult,
  urlResults: UrlAnalysisResult[] = []
): SignalExtractionResult {
  const signals: ExtractedSignal[] = [];
  const linguisticAnomalies: string[] = [];

  const textToScan = normalized.normalizedText;

  // 1. Scan against Deterministic Rules Matrix
  for (const rule of DETERMINISTIC_RULES) {
    let matchesPositive = false;
    let matchingSnippet = '';

    for (const posRegex of rule.positivePatterns) {
      const match = textToScan.match(posRegex);
      if (match) {
        matchesPositive = true;
        matchingSnippet = match[0];
        break;
      }
    }

    if (matchesPositive) {
      // Check negative intent patterns (hard negatives / security alerts)
      let matchesNegative = false;
      if (rule.negativePatterns) {
        for (const negRegex of rule.negativePatterns) {
          if (negRegex.test(textToScan)) {
            matchesNegative = true;
            break;
          }
        }
      }

      // Only fire signal if it is NOT a negative/legitimate context
      if (!matchesNegative) {
        signals.push({
          id: `${rule.id}-${Date.now()}-${signals.length}`,
          featureId: rule.featureId,
          detected: true,
          severity: rule.severity,
          confidence: 'high',
          source: 'text',
          evidenceText: matchingSnippet,
          explanation: rule.explanation,
        });
      }
    }
  }

  // 2. Text Impersonation check (claiming to be a known entity)
  for (const entity of IMPERSONATION_KEYWORDS) {
    const match = textToScan.match(entity.pattern);
    if (match) {
      signals.push({
        id: `text-impersonation-${Date.now()}-${signals.length}`,
        featureId: 'impersonation',
        detected: true,
        severity: 'high',
        confidence: 'medium',
        source: 'text',
        evidenceText: match[0],
        explanation: `الرسالة تذكر اسماً أو صفة لجهة اعتبارية (${entity.name})، ويجب التأكد من مصداقية القناة والمصدر.`,
      });
      break;
    }
  }

  // 3. Obfuscation & Arabizi linguistic anomalies
  if (normalized.hasObfuscation) {
    linguisticAnomalies.push('اكتشاف محاولات تباعد غير طبيعي بين الأحرف للتمويه والالتفاف على أنظمة الفرز.');
  }
  if (normalized.hasArabizi) {
    linguisticAnomalies.push('استخدام أرقام العربيزي داخل الكلمات للتحايل على فلاتر الكلمات المحظورة.');
  }

  // 4. Merge signals from all extracted URLs
  for (const urlRes of urlResults) {
    for (const urlSig of urlRes.signals) {
      signals.push(urlSig);
    }
  }

  // 5. Compute detected features and critical status
  const detectedFeatures = Array.from(new Set(signals.map((s) => s.featureId)));
  const hasCriticalThreat = signals.some((s) => s.severity === 'high');

  return {
    signals,
    hasCriticalThreat,
    detectedFeatures,
    linguisticAnomalies,
  };
}
