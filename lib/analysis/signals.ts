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
 * Maps a match found in normalized text back to the verbatim substring in originalText.
 * This guarantees strict provenance and containment for evidence quotes.
 */
function extractRawSnippet(normalizedSnippet: string, originalText: string): string {
  if (!normalizedSnippet || !originalText) return normalizedSnippet;
  if (originalText.includes(normalizedSnippet)) {
    return normalizedSnippet;
  }
  try {
    const escapedChars = normalizedSnippet.split('').map((ch) => {
      if (ch === 'ا') return '[اأإآٱ]';
      if (ch === 'ه') return '[هة]';
      if (ch === 'ي') return '[يىئ]';
      if (ch === 'و') return '[وؤ]';
      if (/\s/.test(ch)) return '[\\s\\u200B-\\u200D\\uFEFF\\u00A0]+';
      if (/[.*+?^${}()|[\]\\]/.test(ch)) return '\\' + ch;
      return ch;
    });
    const pattern = escapedChars.join('[\\u064B-\\u065F\\u0670\\u0640\\u200B-\\u200D\\uFEFF]*');
    const m = originalText.match(new RegExp(pattern, 'i'));
    if (m) {
      return m[0];
    }
  } catch {
    // fallback
  }
  return normalizedSnippet;
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
      /(?:رمز|كود)\s+(?:التحقق|التاكيد|otp)\s+(?:المرسل|المطلوب|لتفعيل|لتاكيد|لتحديث)\s+(?:ادخل|ارسل|افتح|اضغط|هنا)/i,
      /(?:سوي|اعمل|اكد|تاكيد)\s+(?:تاكيد\s+)?(?:لـ?)?(?:رمز|كود)\s+(?:التحقق|التاكيد|otp)/i,
      /(?:خش|ادخل|افتح)\s+(?:هذا\s+)?(?:الرابط|اللينك).*(?:رمز|كود)\s+(?:التحقق|التاكيد|otp)/i,
      /(?:enter|send|share|provide)\s+(?:your\s+)?(?:otp|verification\s+code|security\s+code)/i,
      /(?:7ot|hot|dakhel|ed5ol|eb3t|ersel|share)\s+(?:bـ)?(?:el\s+)?(?:otp|code|ramz)/i,
      /(?:otp|code|ramz)\s+(?:el\s+)?(?:ta2keed|t7qeeq|d5ol)/i,
    ],
    negativePatterns: [
      /(?:لا\s+تشارك|احذر\s+من\s+مشاركة|لن\s+يطلب|لا\s+تعط|للحفاظ\s+على|تنبيه\s+امني|تذكير\s+امني|تحذير\s+امني|هو\s*:?\s*\[?otp\]?|هو\s*:?\s*\d{4,6}|صالح\s+لمدة|never\s+share|do\s+not\s+share|warns?\s+you)/i,
      /(?:اياك|اياكم)\s+(?:و|ان\s+)?(?:مشاركه|مشاركة|ارسال|اعطاء|تشارك|ترسل|تعط)/i,
      /حذار\s+من\s+(?:مشاركه|مشاركة|ارسال|اعطاء)/i,
    ],
    explanation: 'طلب صريح لإدخال أو مشاركة رمز التحقق لمرة واحدة (OTP) المخصص للمصادقة وتأكيد العمليات.',
  },

  // 2. Credential Request (Strictly requiring sensitive credentials or explicit credential entry with links)
  {
    id: 'rule-credential-request',
    featureId: 'credential_request',
    severity: 'high',
    positivePatterns: [
      /(?:يرجى\s+)?(?:ادخل|ادخال|حدث|تحديث|اكتب|تسجيل|تاكيد|ارسل|ارسال|زودنا|تزويدنا|اعطني|ضع)\s+(?:بيانات|معلومات|رقم\s+الهويه\s+و|رقم\s+الهوية\s+و)?\s*(?:كلمه\s+(?:ال)?مرور|الرقم\s+السري|كلمه\s+السر|رمز\s+الامان|رمز\s+الحمايه|password|pin|cvv|رقم\s+البطاقه|بيانات\s+الدخول|بيانات\s+البطاقه)/i,
      /(?:ادخل|ادخال|ارسل|ارسال|شارك|مشاركه|زودنا|اكتب|ضع)\s+(?:رقم\s+البطاقه|رمز\s+الامان|رمز\s+الحمايه|cvv|pin)/i,
      /(?:تحديث|تاكيد|تنشيط)\s+(?:بياناتك|حسابك|بطاقتك).*(?:وادخال|بادخال|مع|ثم\s+ادخل)\s*(?:كلمه\s+(?:ال)?مرور|الرقم\s+السري|رمز\s+الامان|بيانات\s+الدخول|بيانات\s+البطاقه)/i,
      /(?:تحديث|تاكيد|تنشيط|ادخال|ارسال)\s+(?:بياناتك|معلوماتك)\s+(?:البنكيه|المصرفيه|الائتمانيه)/i,
      /(?:تحديث|تاكيد)\s+بياناتك\s+البنكيه/i,
      /(?:يتوجب|يجب|يلزم|مطلوب).{0,35}(?:ادخال|تاكيد|تحديث)\s+كلمه\s+(?:ال)?مرور/i,
      /(?:enter|update|verify|confirm|provide|send)\s+(?:your\s+)?(?:password|card\s+number|cvv|pin|login\s+credentials)/i,
      /(?:rkm|raqam)\s+(?:el\s+)?(?:karta|bitaqa|card|el\s+card)/i,
      /(?:eb3t|hot|7ot|ersel|dakhel|ed5ol|send)\s+.*(?:rkm|raqam|karta|bitaqa|password|pass|pin|cvv)/i,
    ],
    negativePatterns: [
      /(?:لن\s+يطلب|لا\s+تشارك|احذر|لا\s+تعط|لا\s+ترسل|لا\s+تدخل|غير\s+كلمه\s+(?:ال)?مرور|تغيير\s+دوري|نصيحه\s+امنيه|تنبيه\s+امني|تذكير\s+امني|never\s+share|do\s+not\s+share)/i,
      /(?:اياك|اياكم)\s+(?:و|ان\s+)?(?:مشاركه|مشاركة|ارسال|اعطاء|تشارك|ترسل|تعط)/i,
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
      /(?:قبل\s+انتهاء\s+(?:الدوام|الوقت|المهله|الفتره))/i,
      /(?:قبل\s+الساعه\s+\d+|قبل\s+الموعد|قبل\s+الاغلاق)/i,
      /(?:immediately|urgent|within\s+\d+\s+(?:hours?|mins?|days?)|limited\s+time)/i,
      /\b(?:bsor3a|bsor3ah|fawran|3ajel|darori)\b/i,
    ],
    negativePatterns: [
      /(?:ابلاغنا|للبلاغ|الابلاغ|اتصل\s+للبلاغ|تحذير\s+امني|تنبيه\s+امني|تذكير\s+امني)/i,
    ],
    explanation: 'ممارسة ضغط زمني مصطنع لإرباك المستخدم ودفعه للاستجابة السريعة دون تدقيق.',
  },

  // 4. Threat & Intimidation Language
  {
    id: 'rule-threat-language',
    featureId: 'threat_language',
    severity: 'high',
    positivePatterns: [
      /(?:سيتم|سوف\s+يتم|تم)\s+(?:ايقاف|تجميد|حظر|تعليق|قفل|الغاء|ايق[\u0430a]ف)(?:ه)?(?:\s+(?:حسابك|بطاقتك|خدماتك|شحنتك|محفظتك))?/i,
      /(?:حسابك|محفظتك)\s+(?:راح|سوف|رح)?\s*(?:يتقفل|يتجمد|يوقف)/i,
      /(?:7sabk|7sabek|7sabok|account)\s+(?:t36l|et3tl|twaqaf|waqf|tjmed|tjamad|blocked|suspended)/i,
      /(?:لتجنب\s+الغرامه|فرض\s+غرامه|مسائله\s+قانونيه|اجراء\s+قضائي|ايقاف\s+الخدمات|امر\s+قبض|القاء\s+القبض)/i,
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
      /(?:مبروك|تهانينا|الف\s+مبروك)?\s*(?:ربحت|فزت|كسبت|حصلت\s+على)\s+(?:معنا|معانا)?\s*ب?(?:جائز|جايز|مبلغ|سياره|قسيمه|هديه|منحه|مكافاه)/i,
      /(?:منحه\s+ماليه|(?:جائز|جايز)[هه]\s+نقديه|مكافاه\s+ماليه|شيك\s+بنكي)/i,
      /(?:باقه|شحن|رصيد|انترنت|نت)(?:\s+[^\s]{3,15})?\s+(?:مجاني|مجانيه|بالمجان)/i,
      /(?:لتفعيل|استلام|الحصول\s+على|و?استلم|و?احصل\s+على)\s+(?:باقه|رصيد|انترنت|هديه|مكافاه|جائز|جايز)/i,
      /(?:لك|عندك|توجد)?\s*حواله\s+ماليه\s+(?:معلقه|بمبلغ)/i,
      /(?:استثمار\s+مضمون|ارباح\s+يوميه|دخل\s+اضافي\s+مضمون|ثراء\s+سريع)/i,
      /(?:ربح|مكسب|تحقيق|ارباح)\s+(?:عشره|خمسه|مضاعف[هه]?|\d+)\s+(?:اضعاف|مرات|ضعف)/i,
      /(?:ربح|ارباح|عائد|عوائد)\s*(?:مضمون[هه]?|خياليه|ثابت[هه]?)\s*(?:بنسبه\s*)?(?:\d+\s*%|\d+\s*بالمائه)/i,
      /(?:استثمار\s+صغير|بدخول\s+استثمار).*(?:ربح|مكسب|عائد)/i,
      /(?:نحن\s+)?(?:دفع\s+لك|سندفع\s+لك|راتب|عموله)\s+\d+\s*(?:دولار|ريال|يورو|جنيه).{0,35}(?:عمل\s+بسيط|تقييم|من\s+المنزل)/i,
      /(?:صندوق\s+ملايين|تركه\s+ماليه\s+ضخمه|ملايين\s+الدولارات\s+في\s+صندوق)/i,
      /(?:congratulations|you\s+won|won\s+(?:a\s+)?prize|guaranteed\s+returns?)/i,
      /(?:fzt|rb7t|kasabt|reb7t)\s+(?:b|m3)\s+(?:\d+|alf|dollar|mlyon|ja2eza|prize)/i,
      /(?:mbroo*k|mabrouk|alf\s+mbroo*k|tahanina)\s+(?:fzt|rb7t|kasabt)/i,
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
      /(?:رسوم|مبلغ)\s+(?:فك\s+التعليق|التخليص|فك\s+الحظر|التحويل|فك\s+تجميد)/i,
      /(?:سداد|دفع|تحويل)\s+رسوم\s+(?:شهاده|شهادة|نقل|توثيق|تخليص|معامله|معاملة|تسليم|صرف)/i,
      /(?:سداد|دفع|تحويل)\s+رسوم\s+.{0,35}(?:اولا|مقدما)/i,
      /(?:تحويل|دفع|سداد)\s+(?:\d+\s+)?(?:ريال|دولار|مبلغ).{0,35}(?:لحساب|عبر)/i,
      /(?:تحويل|ارسال|ايداع)\s+(?:رصيدك|مبلغك|اموالك)\s+(?:الان\s+)?الي\s+(?:المحفظه|حساب)/i,
      /(?:لتسليم|لاعطاء|ارسال|تزويد|تسليم)\s+(?:كود|رمز|رقم)\s+(?:الحواله|الصرف|السحب)/i,
      /(?:pay|transfer|settle)\s+(?:delivery|customs|clearance|shipping)\s+fees?/i,
      /(?:rosoom|roosoom)\s+(?:el\s+)?(?:twseel|twsil|sh7n|tawseel)/i,
      /(?:tdfe3|edfa3|adfa3|daf3|pay)\s+(?:\d+\s+)?(?:riyal|dollar|rosoom|fees?)/i,
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

  // 8. Action Pressure (Urgent CTA & Direct Social Action)
  {
    id: 'rule-action-pressure',
    featureId: 'action_pressure',
    severity: 'medium',
    positivePatterns: [
      /(?:اضغط|انقر|سجل\s+عبر)\s+(?:على\s+)?(?:رابط|الرابط)(?:\s+(?:التسجيل|الدخول|هنا))?/i,
      /(?:و)?(?:افتح|ادخل|زور|راجع)\s+(?:هذا\s+)?(?:الرابط|اللينك)/i,
      /(?:ادخل|سجل|اضغط|انقر)\s+هنا(?:\s|$|[.,!؟])/i,
      /(?:سارع\s+بالتسجيل|سارع\s+بالدخول|تابع\s+الرابط)/i,
      /(?:ادخل|سجل|اكتب)\s+(?:رقم\s+)?(?:هاتفك|جوالك|رقمك)\s+(?:هنا|لتفعيل|للحصول)/i,
      /(?:توجه\s+لـ?اقرب\s+صراف|توجه\s+الى\s+الصراف)/i,
      /(?:تواصل\s+مع.*عبر\s+الاتصال|اتصل\s+(?:فورا|حالا|الان|بالرقم)|الاتصال\s+بالرقم)/i,
      /(?:اتصل|تواصل)\s+(?:حالا|فورا|الان|بسرعه)?\s*(?:على|عبر|بالرقم)?\s*\[?phone\]?/i,
      /(?:ارسل|ارسال|مراسله)\s+(?:رساله\s+)?واتساب|تواصل\s+(?:عبر|على)?\s*واتساب/i,
      /(?:click\s+here|follow\s+link|visit\s+link\s+now)/i,
      /(?:d5ol|ed5ol|ed5ol\s+3la|click|ezor)\s+(?:el\s+)?(?:rabet|link)/i,
      /(?:شاهد|تصفح|عرض|تحميل|حمل|استلم)\s+.{0,40}من\s+هنا|من\s+هنا\s*[:：]/i,
    ],
    explanation: 'حث ملح على النقر أو الاتصال أو التوجه المباشر لاتخاذ الإجراء المطلوب فوراً.',
  },

  // 9. Unexpected Contact / Unsolicited Selection
  {
    id: 'rule-unexpected-contact',
    featureId: 'unexpected_contact',
    severity: 'medium',
    positivePatterns: [
      /(?:تم\s+اختيار\s+(?:رقمك|رقم\s+هاتفك|شريحتك|حسابك)|تم\s+ترشيحك\s+للفوز)/i,
      /(?:اتصال\s+مفاجئ|رساله\s+غير\s+متوقعه|من\s+رقم\s+جديد\s+وغير\s+مسجل)/i,
      /(?:في\s+سحب|نتيجه\s+سحب|سحب\s+مهرجان)/i,
      /(?:your\s+number\s+was\s+selected|you\s+have\s+been\s+selected)/i,
      /(?:بطاق[هه]|كارت|صور[هه])\s+(?:(?:ال)?(?:معايده|تهنئه))?\s*.{0,25}(?:المهدا[هه]\s+لك|باسمك|(?:ال)?خاص[هه]?\s+بك)/i,
    ],
    explanation: 'إشعار مفاجئ باختيار المستخدم أو الفوز دون مشاركة أو اشتراك مسبق.',
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
  { name: 'جهة مصرفية / بنك', pattern: /(?:مصرف|بنك|بطاقتك\s+المصرفيه|حسابك\s+البنكي)/i },
  { name: 'بنك الكريمي', pattern: /(?:بنك\s+)?الكريمي|صراف\s+كريمي/i },
  { name: 'شبكة النجم للصرافة', pattern: /(?:شبكه\s+)?النجم(?:\s+للصرافه)?/i },
  { name: 'البنك المركزي', pattern: /البنك\s+المركزي/i },
  { name: 'واتساب', pattern: /(?:واتساب|whatsapp)/i },
  { name: 'أبشر', pattern: /(?:منصه|بوابه)?\s*ابشر/i },
  { name: 'البريد السعودي (سبل)', pattern: /(?:البريد\s+السعودي|سبل|شحنتك\s+رقم)/i },
  { name: 'أرامكس', pattern: /(?:ارامكس|aramex)/i },
  { name: 'دي إتش إل', pattern: /(?:دي\s+ايتش\s+ال|dhl)/i },
  { name: 'شركة الاتصالات (stc)', pattern: /(?:stc|الاتصالات\s+السعوديه)/i },
  { name: 'الزكاة والضريبة', pattern: /(?:هيئه\s+الزكاه|زكاه\s+ودخل|zatca)/i },
  { name: 'جهة قضائية / حكومية', pattern: /(?:الهيئه\s+العامه|وزاره\s+العدل|المحكمه|محكمه|قضائيه|امر\s+قبض)/i },
];

/**
 * Contextual Impersonation Patterns (Entity claim / Pretending to represent entity)
 */
const EXPLICIT_IDENTITY_CLAIM_PATTERNS = [
  /(?:نحن\s+(?:من|فريق)?|معك|انا|فريق\s+دعم|خدمه\s+العملاء|خدمه\s+عملاء|دعم\s+فني|موظف|اداره)\s+(?:من\s+)?(?:مصرف|بنك|منصه|شركه|بوابه)?\s*(?:الراجحي|الاهلي|الرياض|الانماء|ابشر|البريد|سبل|ارامكس|dhl|smsa|stc|الكريمي|النجم)/i,
  /(?:موظف|ممثل|اداره|فريق\s+دعم|خدمه\s+عملاء|مسؤول\s+الحسابات)\s+(?:البنك|المصرف|الشركه|المنصه)(?!\s+(?:لن\s+يطلب|لا\s+يطلب))/i,
  /(?:حسابك|بطاقتك|شحنتك)\s+(?:في|لدى|مع)\s*(?:الراجحي|الاهلي|الرياض|الانماء|ابشر|البريد|سبل|ارامكس|dhl|smsa|stc|الكريمي|النجم)/i,
  /(?:تم|سيتم)\s+(?:ايقاف|تجميد|حظر|قفل|تعليق|ايق[\u0430a]ف)\s+(?:حسابك|بطاقتك|محفظتك)/i,
  /(?:تم|سيتم)\s+(?:ايقاف|تجميد|حظر|قفل|تعليق)\s+(?:حسابك|بطاقتك)\s+(?:في|لدى)?\s*(?:الراجحي|الاهلي|الرياض|الانماء|ابشر|البريد|سبل|الكريمي)/i,
  /(?:اداره|منحه|اشعار|قرار)\s+.{0,30}(?:من\s+)?البنك\s+المركزي/i,
  /(?:مسؤول\s+الحسابات|خدمة\s+العملاء)\s+عبر\s+الرقم/i,
  /(?:تهديكم\s+الهيئه|نفيدكم\s+بوجود\s+غرامه|صدور\s+امر\s+قبض)/i,
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
          // Find corresponding match in originalText to preserve exact raw characters
          const rawMatchText = extractRawSnippet(clausePositiveMatch, normalized.originalText);

          signals.push({
            id: `${rule.id}-${Date.now()}-${signals.length}`,
            featureId: rule.featureId,
            detected: true,
            severity: rule.severity,
            confidence: 'high',
            source: 'text',
            evidenceText: rawMatchText,
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
          const hasLocalNegation =
            /(?:لا\s+تشارك|احذر|لن\s+يطلب|لا\s+ترسل|لا\s+تعط|(?:اياك|اياكم)\s+(?:و|ان\s+)?(?:مشاركه|مشاركة|ارسال|اعطاء|تشارك|ترسل|تعط)|حذار\s+من|تذكير\s+امني|تحذير\s+امني)/i.test(
              clause
            );

          if (hasLocalNegation) continue;

          const sendDirective = clause.match(
            /(?:ارسل|ادخل|شارك|اعطني|زودني)(?:ه)?\s+(?:لي|لنا|هنا)?\s*(?:فورا|الان)?/i
          );

          if (sendDirective) {
            signals.push({
              id: `${rule.id}-anaphora-${Date.now()}-${signals.length}`,
              featureId: 'otp_request',
              detected: true,
              severity: 'high',
              confidence: 'high',
              source: 'text',
              evidenceText: extractRawSnippet(sendDirective[0], normalized.originalText),
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
        evidenceText: extractRawSnippet(identityEvidence || mentionedEntity.match, normalized.originalText),
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
