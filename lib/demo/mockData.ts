import { AnalysisResult, DemoScenario } from '../types/analysis';

/**
 * HARIS (حارس) — Mock Demo Scenarios & Baseline Mock Results
 * NOTE: This file is strictly for Phase 2 UI design and demo demonstration.
 * No real AI processing is performed here.
 */

export const mockDefaultResult: AnalysisResult = {
  isMockData: true,
  inputMode: 'text',
  inputPreview: 'عزيزي العميل، تم إيقاف بطاقتك الائتمانية مؤقتاً لأسباب أمنية. يرجى تحديث بياناتك فوراً خلال ساعتين لتجنب الغرامة عبر الرابط: https://alrajhi-secure-login.xyz/verify وإدخال رمز التحقق المرسل لهاتفك.',
  riskScore: 91,
  riskLevel: 'high',
  scamType: 'انتحال جهة مالية ومصرفية',
  summary: 'تم رصد مؤشرات احتيال هندسة اجتماعية عالية الخطورة؛ الرسالة تدعي كذباً تجميد الحساب المصرفي وتمارس ضغطاً زمنياً شديداً لدفعك لإدخال بيانات اعتمادك ورمز التحقق عبر نطاق خبيث.',
  scamDna: [
    {
      id: 'urgency',
      nameAr: 'الاستعجال وضغط الوقت',
      nameEn: 'Urgency & Pressure',
      detected: true,
      severity: 'high',
      detail: 'استخدام عبارات التهديد بإيقاف الحساب خلال ساعتين لإرباك الضحية ومنعها من التفكير العقلاني.',
    },
    {
      id: 'impersonation',
      nameAr: 'انتحال الهوية',
      nameEn: 'Identity Impersonation',
      detected: true,
      severity: 'high',
      detail: 'انتحال صفة مصرف الراجحي دون استخدام البريد أو القنوات المصرفية الرسمية المعتمدة.',
    },
    {
      id: 'credential_request',
      nameAr: 'طلب معلومات حساسة',
      nameEn: 'Credential Harvesting',
      detected: true,
      severity: 'high',
      detail: 'محاولة الاستيلاء على أرقام البطاقة وكلمة المرور من خلال صفحة تصيد ملغومة.',
    },
    {
      id: 'otp_request',
      nameAr: 'طلب رمز التحقق (OTP)',
      nameEn: 'OTP Interception',
      detected: true,
      severity: 'high',
      detail: 'طلب إدخال رمز التحقق لمرة واحدة في الصفحة للسيطرة الكاملة على الحساب البنكي.',
    },
    {
      id: 'suspicious_url',
      nameAr: 'رابط احتيالي مشبوه',
      nameEn: 'Suspicious Domain',
      detected: true,
      severity: 'high',
      detail: 'النطاق المستخدم (.xyz) مسجل حديثاً ويحاكي اسم البنك لخداع المستخدم، ولا يرتبط بالنطاق الرسمي للبنك.',
    },
    {
      id: 'financial_lure',
      nameAr: 'حافز مالي / ادعاء مكافأة',
      nameEn: 'Financial Lure',
      detected: false,
      severity: 'low',
      detail: 'لم يُرصد وعد بمكافأة؛ تم استخدام أسلوب الترهيب والتهديد المالي بدلاً من الإغراء.',
    },
  ],
  evidence: [
    {
      id: 'ev-1',
      title: 'تهديد زمني وتخويف من غرامة مالية',
      description: 'الرسالة تدعي إيقاف البطاقة خلال ساعتين وفرض غرامة، وهي أساليب لا تستخدمها البنوك المرخصة إطلاقاً.',
      severity: 'high',
      source: 'linguistic',
    },
    {
      id: 'ev-2',
      title: 'نطاق تصيد منتحل للعلامة التجارية',
      description: 'الرابط `alrajhi-secure-login.xyz` يستخدم نطاقاً غير مصرفي (.xyz) ويهدف لاصطياد الضحايا.',
      severity: 'high',
      source: 'technical',
    },
    {
      id: 'ev-3',
      title: 'محاولة استدراج رمز التحقق لمرة واحدة (OTP)',
      description: 'البنوك تنص دائماً على أن موظفيها لن يطلبوا رمز التحقق الخاص بك تحت أي ظرف.',
      severity: 'high',
      source: 'behavioral',
    },
  ],
  actionableAdvice: [
    'لا تضغط على الرابط نهائياً ولا تدخل أي معلومة في الصفحة.',
    'لا تشارك رمز التحقق (OTP) المرسل على هاتفك مع أي شخص أو موقع غير موثوق.',
    'تواصل فوراً مع مصرفك عبر الرقم الرسمي المطبوع خلف بطاقتك البنكية.',
    'أبلغ عن الرسالة المشبوهة للجهات الأمنية وقنوات مكافحة الاحتيال الرسمية (مثل 330330 في السعودية).',
  ],
  uncertainties: [
    'لم يتم تتبع الرابط أو زيارته من خوادمنا تجنباً لتنشيط البرمجيات الخبيثة وتأكيداً لسياسة الأمان السلبي.',
    'التقييم مستند إلى المؤشرات الرقمية والهندسية المستخرجة ولا يمثل حكماً قانونياً قاطعاً.',
  ],
  analyzedAt: 'منذ قليل',
};

export const demoScenarios: DemoScenario[] = [
  {
    id: 'RED-013',
    title: 'تصيد بنكي بالأرابيزي لسرقة OTP',
    badge: 'أرابيزي وتصيد',
    mode: 'text',
    description: 'رسالة احتيال مصرفية مكتوبة بالأرابيزي تدعي تعطل الحساب وتطلب إدخال رمز التحقق OTP عبر رابط مشبوه.',
    content: 'ya 5oy 7sabk t36l 3shan el t7deeth. d5ol hna w 7ot el OTP bsor3a: https://bank-login.top/auth',
    mockResult: mockDefaultResult,
  },
  {
    id: 'RED-034',
    title: 'تمويه برابط رسمي مع رابط تصيد',
    badge: 'روابط مزدوجة وتضليل',
    mode: 'text',
    description: 'رسالة تدمج رابط مصرف رسمي لطمأنة الضحية مع رابط تصيد بنكي خبيث لطلب البيانات.',
    content: 'عزيزي العميل، حرصاً على أمانك يمكنك مراجعة شروط الخدمة عبر موقعنا الرسمي https://alrajhibank.com.sa ولكن لتحديث بياناتك البنكية الآن افتح: https://alrajhi-update.top/auth',
    mockResult: mockDefaultResult,
  },
  {
    id: 'RED-043',
    title: 'تهنئة عيد فطر دافئة ملغمة برابط خبيث',
    badge: 'غلاف معايدة ملغم',
    mode: 'text',
    description: 'بطاقة معايدة احتفالية دافئة تخفي استدراجاً لفتح رابط احتيالي غير آمن (.click) بزعم استلام بطاقة خاصة.',
    content: 'كل عام وأنتم بألف خير بمناسبة عيد الفطر المبارك، أعاده الله عليكم باليمن والبركات. شاهد بطاقة المعايدة المهداة لك باسمك من هنا: https://eid-mubarak.click/card',
    mockResult: mockDefaultResult,
  },
];

