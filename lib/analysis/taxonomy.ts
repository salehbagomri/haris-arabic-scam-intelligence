/**
 * HARIS (حارس) — Central Scam Taxonomy & Threat DNA Definitions
 *
 * Single source of truth for all scam types, Scam DNA features, and metadata.
 * All modules (normalizer, urlAnalyzer, signals, riskEngine, and future AI prompts)
 * MUST strictly reference these definitions.
 */

export const SCAM_TYPES = [
  'BANK_IMPERSONATION',
  'GOVERNMENT_IMPERSONATION',
  'DELIVERY_SCAM',
  'FAKE_PRIZE',
  'JOB_SCAM',
  'INVESTMENT_SCAM',
  'ACCOUNT_TAKEOVER',
  'SOCIAL_ENGINEERING',
  'PAYMENT_SCAM',
  'UNKNOWN',
] as const;

export type ScamType = (typeof SCAM_TYPES)[number];

export const SCAM_DNA_FEATURES = [
  'urgency',
  'credential_request',
  'otp_request',
  'impersonation',
  'financial_lure',
  'suspicious_url',
  'threat_language',
  'unexpected_contact',
  'secrecy_pressure',
  'suspicious_payment_request',
  'action_pressure',
] as const;

export type FeatureKey = (typeof SCAM_DNA_FEATURES)[number];

export type SignalSource = 'text' | 'url' | 'rule' | 'ai';
export type Severity = 'low' | 'medium' | 'high';
export type Confidence = 'low' | 'medium' | 'high';

export interface FeatureMetadata {
  id: FeatureKey;
  nameAr: string;
  nameEn: string;
  descriptionAr: string;
  defaultSeverity: Severity;
}

export interface ScamTypeMetadata {
  id: ScamType;
  nameAr: string;
  nameEn: string;
  descriptionAr: string;
  primaryFeatures: FeatureKey[];
}

export interface ExtractedSignal {
  id: string;
  featureId: FeatureKey;
  detected: boolean;
  severity: Severity;
  confidence: Confidence;
  source: SignalSource;
  evidenceText: string;
  explanation: string;
}

export const SCAM_DNA_METADATA: Record<FeatureKey, FeatureMetadata> = {
  urgency: {
    id: 'urgency',
    nameAr: 'الاستعجال وضغط الوقت',
    nameEn: 'Urgency Pressure',
    descriptionAr: 'استخدام أسلوب ضغط الوقت والمهل الزمنية الضيقة لدفع الضحية لاتخاذ قرار متسرع دون تفكير.',
    defaultSeverity: 'high',
  },
  credential_request: {
    id: 'credential_request',
    nameAr: 'طلب معلومات حساسة واعتماد الدخول',
    nameEn: 'Credential Harvesting',
    descriptionAr: 'محاولة استدراج كلمات المرور أو أرقام الهوية أو بيانات البطاقة المصرفية ورمز CVV.',
    defaultSeverity: 'high',
  },
  otp_request: {
    id: 'otp_request',
    nameAr: 'طلب رمز التحقق لمرة واحدة (OTP)',
    nameEn: 'OTP Interception',
    descriptionAr: 'محاولة صريحة لطلب مشاركة أو إدخال رمز التحقق المؤقت المرسل عبر الرسائل القصيرة للسيطرة على الحساب.',
    defaultSeverity: 'high',
  },
  impersonation: {
    id: 'impersonation',
    nameAr: 'انتحال الهوية والعلامات التجارية',
    nameEn: 'Brand / Entity Impersonation',
    descriptionAr: 'ادعاء تمثيل بنك أو جهة حكومية أو شركة توصيل مرموقة لاكتساب مصداقية زائفة.',
    defaultSeverity: 'high',
  },
  financial_lure: {
    id: 'financial_lure',
    nameAr: 'حافز مالي وجوائز وهمية',
    nameEn: 'Financial Lure',
    descriptionAr: 'إغراء الضحية بجوائز نقدية، مبالغ غير متوقعة، أو عوائد استثمارية خيالية وسريعة.',
    defaultSeverity: 'high',
  },
  suspicious_url: {
    id: 'suspicious_url',
    nameAr: 'رابط خارجي مشبوه',
    nameEn: 'Suspicious URL / Domain',
    descriptionAr: 'احتواء المحتوى على رابط يستخدم نطاقاً رخيصاً، تقصيراً، انتحالاً بالنطاقات الفرعية، أو عنوان IP مباشر.',
    defaultSeverity: 'high',
  },
  threat_language: {
    id: 'threat_language',
    nameAr: 'لغة التهديد والترهيب',
    nameEn: 'Threat Language',
    descriptionAr: 'التهديد بتجميد الحسابات، فرض غرامات، أو اتخاذ إجراءات قانونية وأمنية لإخافة الضحية.',
    defaultSeverity: 'high',
  },
  unexpected_contact: {
    id: 'unexpected_contact',
    nameAr: 'تواصل مفاجئ وغير متوقع',
    nameEn: 'Unexpected Contact',
    descriptionAr: 'وصول رسالة من جهة غير مألوفة أو عبر وسيط غير رسمي كالرسائل القصيرة أو برامج الدردشة.',
    defaultSeverity: 'medium',
  },
  secrecy_pressure: {
    id: 'secrecy_pressure',
    nameAr: 'الضغط للحفاظ على السرية',
    nameEn: 'Secrecy Pressure',
    descriptionAr: 'مطالبة الضحية بعدم استشارة الآخرين أو الاحتفاظ بالمحادثة سراً لتفادي انكشاف المخطط.',
    defaultSeverity: 'high',
  },
  suspicious_payment_request: {
    id: 'suspicious_payment_request',
    nameAr: 'طلب سداد أو تحويل مالي مشبوه',
    nameEn: 'Suspicious Payment Request',
    descriptionAr: 'المطالبة برسوم تخليص، رسوم توصيل رمزية، بطاقات هدايا، أو تحويل مالي لحسابات غير رسمية.',
    defaultSeverity: 'high',
  },
  action_pressure: {
    id: 'action_pressure',
    nameAr: 'حث شديد على اتخاذ إجراء فوري',
    nameEn: 'Call to Action Pressure',
    descriptionAr: 'استخدام أفعال أمر ملحة مثل (سارع بالضغط، حدّث حالاً، استلم هديتك الآن قبل الإلغاء).',
    defaultSeverity: 'medium',
  },
};

export const SCAM_TYPES_METADATA: Record<ScamType, ScamTypeMetadata> = {
  BANK_IMPERSONATION: {
    id: 'BANK_IMPERSONATION',
    nameAr: 'انتحال بنك / مؤسسة مالية',
    nameEn: 'Banking Impersonation',
    descriptionAr: 'ادعاء تمثيل مصرف تجاري لسرقة بيانات الحساب أو البطاقات المصرفية أو رموز التحقق.',
    primaryFeatures: ['impersonation', 'credential_request', 'otp_request', 'threat_language', 'urgency'],
  },
  GOVERNMENT_IMPERSONATION: {
    id: 'GOVERNMENT_IMPERSONATION',
    nameAr: 'انتحال جهة حكومية أو رسمية',
    nameEn: 'Government Entity Impersonation',
    descriptionAr: 'انتحال منصات حكومية (مثل أبشر، الزكاة والضريبة، القضاء) بهدف سرقة الهوية الرقمية أو النصب.',
    primaryFeatures: ['impersonation', 'threat_language', 'action_pressure', 'credential_request'],
  },
  DELIVERY_SCAM: {
    id: 'DELIVERY_SCAM',
    nameAr: 'احتيال شحن وطرود توصيل',
    nameEn: 'Delivery / Courier Scam',
    descriptionAr: 'إشعار كاذب بوجود طرد معلق وطلب سداد رسوم رمزية عبر رابط تصيد لسرقة بيانات البطاقة.',
    primaryFeatures: ['impersonation', 'suspicious_payment_request', 'suspicious_url', 'urgency'],
  },
  FAKE_PRIZE: {
    id: 'FAKE_PRIZE',
    nameAr: 'جوائز ومسابقات وهمية',
    nameEn: 'Fake Prize / Lottery',
    descriptionAr: 'إيهام المستخدم بالفوز بسيارة أو قسيمة شرائية أو مبلغ ضخم مقابل النقر على رابط أو دفع رسوم.',
    primaryFeatures: ['financial_lure', 'action_pressure', 'suspicious_url'],
  },
  JOB_SCAM: {
    id: 'JOB_SCAM',
    nameAr: 'احتيال توظيف وعمل عن بعد',
    nameEn: 'Employment / Job Scam',
    descriptionAr: 'عروض عمل مغرية برواتب عالية وساعات عمل قليلة تهدف لطلب رسوم تسجيل أو استغلال بيانات الضحية.',
    primaryFeatures: ['financial_lure', 'unexpected_contact', 'credential_request'],
  },
  INVESTMENT_SCAM: {
    id: 'INVESTMENT_SCAM',
    nameAr: 'احتيال استثماري وعوائد خيالية',
    nameEn: 'Investment / Ponzi Scam',
    descriptionAr: 'الترويج لاستثمارات وهمية بأسهم أو عملات رقمية تعد بأرباح مؤكدة ومضمونة بنسبة 100%.',
    primaryFeatures: ['financial_lure', 'action_pressure', 'suspicious_payment_request'],
  },
  ACCOUNT_TAKEOVER: {
    id: 'ACCOUNT_TAKEOVER',
    nameAr: 'الاستيلاء على الحسابات الرقمية',
    nameEn: 'Account Takeover',
    descriptionAr: 'محاولة اختراق حساب واتساب أو وسائل التواصل من خلال استدراج رمز التحقق OTP أو روابط المصادقة.',
    primaryFeatures: ['otp_request', 'credential_request', 'secrecy_pressure'],
  },
  SOCIAL_ENGINEERING: {
    id: 'SOCIAL_ENGINEERING',
    nameAr: 'هندسة اجتماعية وتضليل نفسي',
    nameEn: 'Social Engineering',
    descriptionAr: 'استغلال الثقة أو العاطفة أو الفضول لحمل الضحية على ارتكاب خطأ أمني ومشاركة بياناته.',
    primaryFeatures: ['urgency', 'action_pressure', 'unexpected_contact'],
  },
  PAYMENT_SCAM: {
    id: 'PAYMENT_SCAM',
    nameAr: 'احتيال دفع وتحويلات مالية',
    nameEn: 'Payment / Transfer Fraud',
    descriptionAr: 'إرسال فواتير مزورة أو إشعارات إيداع وهمية أو طلب تحويل أموال لحسابات أفراد مشبوهة.',
    primaryFeatures: ['suspicious_payment_request', 'threat_language', 'urgency'],
  },
  UNKNOWN: {
    id: 'UNKNOWN',
    nameAr: 'نمط غير محدد بدقة',
    nameEn: 'Unclassified Pattern',
    descriptionAr: 'محتوى مشبوه لم تتطابق مؤشراته بشكل حاسم مع أي تصنيف محدد من أنماط الاحتيال المعروفة.',
    primaryFeatures: [],
  },
};
