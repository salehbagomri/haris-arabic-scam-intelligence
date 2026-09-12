/**
 * HARIS (حارس) — Deterministic Signal Extractor (Precision Hardened)
 *
 * Implements intent-aware, clause-level rule extraction for Scam DNA features.
 *
 * PRECISION PRINCIPLES:
 * 1. Brand mention alone ≠ Impersonation (requires explicit identity claims, account threats, or paired threat actions).
 * 2. Clause-level local negation (negation in one clause does NOT suppress malicious requests in other clauses).
 * 3. Strict credential requests (generic language like "يمكنك تحديث حسابك من التطبيق" is NOT a credential request).
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
 * Split text into semantic clauses using sentence punctuation and contrastive conjunctions
 */
export function splitIntoClauses(text: string): string[] {
  return text
    .split(/(?:[.,;:\n!?؟،؛]|\b(?:لكن|ولكن|بس|بل|however|but)\b)/i)
    .map((c) => c.trim())
    .filter((c) => c.length > 0);
}

/**
 * Deterministic Signal Pattern Rules Matrix
 */
const DETERMINISTIC_RULES: PatternRule[] = [
  // 1. OTP Request (Intent-aware & Clause-contextual)
  {
    id: 'rule-otp-request',
    featureId: 'otp_request',
    severity: 'high',
    positivePatterns: [
      /(?:و)?(?:ادخل|ادخال|ارسل|ارسال|شارك|مشاركه|زودنا|اكتب|اعطني|ضع)\s+(?:بـ)?(?:رمز|كود|الرمز|الكود)\s+(?:التحقق|التاكيد|السري|المؤقت|otp|code)/i,
      /(?:رمز|كود)\s+(?:التحقق|التاكيد|otp)\s+(?:المرسل|الخاص\s+بك|المطلوب|لتفعيل|لتاكيد|لتحديث)/i,
      /(?:enter|send|share|provide)\s+(?:your\s+)?(?:otp|verification\s+code|security\s+code)/i,
    ],
    negativePatterns: [
      /(?:لا\s+تشارك|احذر\s+من\s+مشاركة|لن\s+يطلب|لا\s+تعط|للحفاظ\s+على|تنبيه\s+امني|never\s+share|do\s+not\s+share|warns?\s+you)/i,
    ],
    explanation: 'طلب صريح لإدخال أو مشاركة رمز التحقق لمرة واحدة (OTP) المخصص للمصادقة وتأكيد العمليات.',
  },

  // 2. Credential Request (Strictly requiring sensitive credentials or explicit credential entry with links)
  {
    id: 'rule-credential-request',
    featureId: 'credential_request',
    severity: 'high',
    positivePatterns: [
      /(?:ادخل|ادخال|حدث|تحديث|اكتب|تسجيل|تاكيد|ارسل|ارسال|زودنا|تزويدنا|اعطني|ضع)\s+(?:بيانات|معلومات)?\s*(?:كلمه\s+المرور|الرقم\s+السري|كلمه\s+السر|رمز\s+الامان|رمز\s+الحمايه|password|pin|cvv|رقم\s+البطاقه|بيانات\s+الدخول|بيانات\s+البطاقه)/i,
      /(?:ادخل|ادخال|ارسل|ارسال|شارك|مشاركه|زودنا|اكتب|ضع)\s+(?:رقم\s+البطاقه|رمز\s+الامان|رمز\s+الحمايه|cvv|pin)/i,
      /(?:تحديث|تاكيد|تنشيط)\s+(?:بياناتك|حسابك|بطاقتك).*(?:وادخال|بادخال|مع|ثم\s+ادخل)\s*(?:كلمه\s+المرور|الرقم\s+السري|رمز\s+الامان|بيانات\s+الدخول|بيانات\s+البطاقه)/i,
      /(?:enter|update|verify|confirm|provide|send)\s+(?:your\s+)?(?:password|card\s+number|cvv|pin|login\s+credentials)/i,
    ],
    negativePatterns: [
      /(?:لن\s+يطلب|لا\s+تشارك|احذر|لا\s+تعط|لا\s+ترسل|لا\s+تدخل|غير\s+كلمه\s+المرور|تغيير\s+دوري|نصيحه\s+امنيه|تنبيه\s+امني|never\s+share|do\s+not\s+share)/i,
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
 * Known Target Entities for Text Impersonation Contextual Evaluation
 */
const IMPERSONATION_TARGET_ENTITIES = [
  { name: 'مصرف الراجحي', pattern: /(?:مصرف|بنك)?\s*الراجحي/i },
  { name: 'البنك الأهلي', pattern: /(?:البنك\s+الاهلي|snb|الاهلي\s+اونلاين)/i },
  { name: 'بنك الرياض', pattern: /بنك\s+الرياض/i },
  { name: 'مصرف الإنماء', pattern: /(?:مصرف|بنك)?\s*الانماء/i },
  { name: 'أبشر', pattern: /(?:منصه|بوابه)?\s*ابشر/i },
  { name: 'البريد السعودي (سبل)', pattern: /(?:البريد\s+السعودي|سبل|شحنتك\s+رقم)/i },
  { name: 'أرامكس', pattern: /(?:ارامكس|aramex)/i },
  { name: 'دي إتش إل', pattern: /(?:دي\s+ايتش\s+ال|dhl)/i },
  { name: 'شركة الاتصالات (stc)', pattern: /(?:stc|الاتصالات\s+السعوديه)/i },
  { name: 'الزكاة والضريبة', pattern: /(?:هيئه\s+الزكاه|زكاه\s+ودخل|zatca)/i },
];

/**
 * Contextual Impersonation Patterns (Entity claim / Pretending to represent entity)
 */
const EXPLICIT_IDENTITY_CLAIM_PATTERNS = [
  /(?:نحن\s+(?:من|فريق)?|معك|انا|فريق\s+دعم|خدمه\s+العملاء|خدمه\s+عملاء|دعم\s+فني|موظف|اداره)\s+(?:من\s+)?(?:مصرف|بنك|منصه|شركه|بوابه)?\s*(?:الراجحي|الاهلي|الرياض|الانماء|ابشر|البريد|سبل|ارامكس|dhl|smsa|stc)/i,
  /(?:موظف|ممثل|اداره|فريق\s+دعم|خدمه\s+عملاء)\s+(?:البنك|المصرف|الشركه|المنصه)/i,
  /(?:حسابك|بطاقتك|شحنتك)\s+(?:في|لدى|مع)\s*(?:الراجحي|الاهلي|الرياض|الانماء|ابشر|البريد|سبل|ارامكس|dhl|smsa|stc)/i,
  /(?:تم|سيتم)\s+(?:ايقاف|تجميد|حظر|قفل|تعليق)\s+(?:حسابك|بطاقتك)\s+(?:في|لدى)?\s*(?:الراجحي|الاهلي|الرياض|الانماء|ابشر|البريد|سبل)/i,
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
  const clauses = splitIntoClauses(textToScan);

  // 1. Scan against Deterministic Rules Matrix at the Clause Level
  for (const rule of DETERMINISTIC_RULES) {
    let ruleMatched = false;

    for (const clause of clauses) {
      if (ruleMatched) break;

      let clausePositiveMatch: string | null = null;
      for (const posRegex of rule.positivePatterns) {
        const match = clause.match(posRegex);
        if (match) {
          clausePositiveMatch = match[0];
          break;
        }
      }

      if (clausePositiveMatch) {
        // Check if this specific clause has local negation
        let clauseNegated = false;
        if (rule.negativePatterns) {
          for (const negRegex of rule.negativePatterns) {
            if (negRegex.test(clause)) {
              clauseNegated = true;
              break;
            }
          }
        }

        // If not negated locally, emit signal
        if (!clauseNegated) {
          signals.push({
            id: `${rule.id}-${Date.now()}-${signals.length}`,
            featureId: rule.featureId,
            detected: true,
            severity: rule.severity,
            confidence: 'high',
            source: 'text',
            evidenceText: clausePositiveMatch,
            explanation: rule.explanation,
          });
          ruleMatched = true;
          break;
        }
      }
    }

    // Special Anaphora check for OTP (e.g. "لا تشارك الرمز مع أحد، لكن أرسله لي فوراً")
    if (!ruleMatched && rule.featureId === 'otp_request') {
      const mentionsOtp = /(?:رمز|كود|الرمز|الكود|otp)/i.test(textToScan);
      if (mentionsOtp) {
        for (const clause of clauses) {
          const sendDirective = clause.match(/(?:ارسل|ادخل|شارك|اعطني|زودني)(?:ه)?\s+(?:لي|لنا|هنا)?\s*(?:فورا|الان)?/i);
          const hasLocalNegation = /(?:لا\s+تشارك|احذر|لن\s+يطلب|لا\s+ترسل|لا\s+تعط)/i.test(clause);

          if (sendDirective && !hasLocalNegation) {
            signals.push({
              id: `${rule.id}-anaphora-${Date.now()}-${signals.length}`,
              featureId: 'otp_request',
              detected: true,
              severity: 'high',
              confidence: 'high',
              source: 'text',
              evidenceText: sendDirective[0],
              explanation: 'طلب صريح لإرسال أو مشاركة رمز التحقق فوراً رغم الإشارة لسرية الرمز.',
            });
            break;
          }
        }
      }
    }
  }

  // 2. Intent-Aware Impersonation Evaluation in Text
  // RULE: A brand mention alone does NOT trigger an impersonation signal!
  // It requires an explicit identity claim OR being paired with credential/threat/payment/OTP/suspicious URL.
  let hasExplicitIdentityClaim = false;
  let identityEvidence = '';

  for (const claimPattern of EXPLICIT_IDENTITY_CLAIM_PATTERNS) {
    const claimMatch = textToScan.match(claimPattern);
    if (claimMatch) {
      hasExplicitIdentityClaim = true;
      identityEvidence = claimMatch[0];
      break;
    }
  }

  // Check if any brand is mentioned in text
  let mentionedEntity: { name: string; match: string } | null = null;
  for (const entity of IMPERSONATION_TARGET_ENTITIES) {
    const match = textToScan.match(entity.pattern);
    if (match) {
      mentionedEntity = { name: entity.name, match: match[0] };
      break;
    }
  }

  if (mentionedEntity) {
    // Determine if there is supporting threat context
    const hasSupportingThreatContext =
      hasExplicitIdentityClaim ||
      signals.some((s) => ['otp_request', 'credential_request', 'threat_language', 'suspicious_payment_request'].includes(s.featureId)) ||
      urlResults.some((u) => u.signals.some((us) => us.featureId === 'suspicious_url' || us.featureId === 'impersonation'));

    if (hasSupportingThreatContext) {
      signals.push({
        id: `text-impersonation-${Date.now()}-${signals.length}`,
        featureId: 'impersonation',
        detected: true,
        severity: 'high',
        confidence: hasExplicitIdentityClaim ? 'high' : 'medium',
        source: 'text',
        evidenceText: identityEvidence || mentionedEntity.match,
        explanation: `انتحال صفة (${mentionedEntity.name}) مقترناً بطلب إجراء أو تهديد أو رابط غير رسمي.`,
      });
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
