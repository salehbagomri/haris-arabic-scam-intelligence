/**
 * HARIS (حارس) — Adversarial Red-Team Dataset (v1.0.0 — Phase 6B)
 *
 * Formal 48-case adversarial corpus specifically authored to stress-test the HARIS
 * intelligence engine across all 16 threat taxonomy categories from RED_TEAM_TAXONOMY.md.
 *
 * Strict Guardrails:
 * - 100% Synthetic and safe authoring.
 * - Zero PII: [PHONE], [OTP], and [ACCOUNT_ID] placeholders strictly enforced.
 * - Arabic-first with rich regional dialects (Yemeni, Gulf, Egyptian, MSA, Arabizi, Mixed EN).
 * - Independent from the 70-case baseline benchmark dataset.
 */

import { RedTeamItem } from './types';
import { SCREENSHOT_FIXTURES } from '../fixtures/screenshots';

export const RED_TEAM_DATASET: RedTeamItem[] = [
  // =========================================================================
  // Category 1: Brand Mention Without Impersonation (Contextual Inversion)
  // =========================================================================
  {
    id: 'RED-001',
    title: 'سؤال استفساري عام عن تطبيق بنك الكريمي (لهجة يمنية)',
    description: 'استفسار بريء في مجموعة دردشة عن تجربة فتح حساب عبر تطبيق الكريمي الجديد.',
    taxonomyCategory: 'brand_mention_no_impersonation',
    dialect: 'yemeni',
    modality: 'text',
    input: {
      text: 'يا جماعة الخير حد جرب يفتح حساب في بنك الكريمي عبر التطبيق الجديد حقهم؟ هل الخدمة سريعة وسابرة ولا أروح الفرع أحسن لي؟',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    forbiddenDnaFeatures: ['impersonation'],
    rationale: 'مجرد ذكر اسم بنك الكريمي في صيغة سؤال للمشورة دون أي ادعاء لتمثيل البنك.',
  },
  {
    id: 'RED-002',
    title: 'مقارنة حيادية لبطاقات مصرف الراجحي (لهجة خليجية)',
    description: 'مقارنة استهلاكية بين بطاقات مصرف الراجحي وبنوك أخرى في منتدى نقاشي.',
    taxonomyCategory: 'brand_mention_no_impersonation',
    dialect: 'gulf',
    modality: 'text',
    input: {
      text: 'السلام عليكم، ايش رأيكم في بطاقة الفرسان من مصرف الراجحي؟ هل تستاهل رسومها السنوية ولا في خيارات أفضل من بنوك ثانية؟',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    forbiddenDnaFeatures: ['impersonation'],
    rationale: 'نقاش مالي عادي يذكر مصرف الراجحي كطرف ثالث دون انتحال أو روابط تصيد.',
  },
  {
    id: 'RED-003',
    title: 'خبر صحفي عام عن شركة الاتصالات السعودية STC (فصحى)',
    description: 'نص إخباري يذكر قيام شركة STC بتوسيع نطاق شبكتها دون طلب أي بيانات.',
    taxonomyCategory: 'brand_mention_no_impersonation',
    dialect: 'msa',
    modality: 'text',
    input: {
      text: 'أعلنت شركة الاتصالات السعودية STC عن إطلاق خدمات الجيل الخامس في مناطق ريفية جديدة اليوم ضمن خطتها لتطوير البنية التحتية الرقمية.',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    forbiddenDnaFeatures: ['impersonation'],
    rationale: 'خبر صحفي محايد يذكر اسم شركة اتصالات دون ادعاء تقديم جوائز أو طلب بيانات.',
  },

  // =========================================================================
  // Category 2: Legitimate OTP Warnings (Polarity Inversion)
  // =========================================================================
  {
    id: 'RED-004',
    title: 'تحذير أمني بنكي ينهى عن مشاركة رمز التحقق OTP (لهجة يمنية)',
    description: 'إشعار توعوي يمني يؤكد أن موظفي الكريمي لن يطلبوا رمز التحقق أبداً.',
    taxonomyCategory: 'legitimate_otp_warnings',
    dialect: 'yemeni',
    modality: 'text',
    input: {
      text: 'تنبيه أمني هام: إدارة مصرف الكريمي لن تطلب منك أبداً الإفصاح عن رمز التحقق OTP أو كلمة السر هاتفياً. احذر من المحتالين ولا تشارك الكود.',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    forbiddenDnaFeatures: ['otp_request'],
    rationale: 'تحذير أمني مع سياق نفي صريح؛ لا يطلب رمز OTP بل يحذر من مشاركته.',
  },
  {
    id: 'RED-005',
    title: 'نصيحة أمنية رسمية توعوية بعدم مشاركة OTP (فصحى)',
    description: 'ملصق توعوي مصرفي رسمي يشدد على سرية رمز OTP.',
    taxonomyCategory: 'legitimate_otp_warnings',
    dialect: 'msa',
    modality: 'text',
    input: {
      text: 'تحذير أمني: موظف البنك لن يطلب منك قط رمز التحقق السري (OTP). يرجى عدم مشاركته مع أي شخص حفاظاً على أموالك وحسابك المصرفي.',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    forbiddenDnaFeatures: ['otp_request'],
    rationale: 'وجود كلمة OTP هنا جاء ضمن سياق نفي وقائي صريح وليس طلباً لرمز التحقق.',
  },
  {
    id: 'RED-006',
    title: 'تذكير أمني صارم ضد الهندسة الاجتماعية (لهجة خليجية)',
    description: 'رسالة نصية تحذر من منتحلي صفة الدعم الفني وتنهى عن مشاركة الرمز لمرة واحدة.',
    taxonomyCategory: 'legitimate_otp_warnings',
    dialect: 'gulf',
    modality: 'text',
    input: {
      text: 'تذكير أمني للعملاء: إياك ومشاركة رمز الدخول لمرة واحدة OTP مع أي متصل يدعي أنه من الدعم الفني أو خدمة العملاء تحت أي ظرف.',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    forbiddenDnaFeatures: ['otp_request'],
    rationale: 'صيغة نهي صريحة (إياك ومشاركة) تحمي المستخدم من التصيد.',
  },

  // =========================================================================
  // Category 3: Legitimate Urgency (Operational Deadlines)
  // =========================================================================
  {
    id: 'RED-007',
    title: 'دعوة طارئة لاجتماع جمعية سكنية محلية (لهجة يمنية)',
    description: 'رسالة إدارية تدعو سكان الحي لاجتماع طارئ لمناقشة فواتير المياه المشتركة.',
    taxonomyCategory: 'legitimate_urgency',
    dialect: 'yemeni',
    modality: 'text',
    input: {
      text: 'عاجل وهام لجميع الجيران: اجتماع طارئ لمجلس إدارة الجمعية السكنية اليوم بعد صلاة المغرب لمناقشة فواتير المياه المشتركة. الحضور إلزامي بالديوان.',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    forbiddenDnaFeatures: ['threat_language'],
    rationale: 'استعجال اجتماعي وتشغيلي بريء للاجتماع الشخصي وليس طلب تحويلات أو تصيد.',
  },
  {
    id: 'RED-008',
    title: 'تذكير بانتهاء مهلة تجديد اشتراك رياضي (لهجة خليجية)',
    description: 'إشعار بانتهاء اشتراك النادي والمطالبة بالحضور لمكتب الاستقبال.',
    taxonomyCategory: 'legitimate_urgency',
    dialect: 'gulf',
    modality: 'text',
    input: {
      text: 'تذكير هام: اشتراكك في النادي الرياضي ينتهي اليوم الساعة 11 مساءً. يرجى زيارة مكتب الاستقبال بالفرع للتجديد قبل انتهاء المهلة.',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    forbiddenDnaFeatures: ['threat_language'],
    rationale: 'موعد إداري روتيني يتطلب حضوراً مادياً للاستقبال ولا يحتوي على روابط إلكترونية.',
  },
  {
    id: 'RED-009',
    title: 'إشعار صعود فوري لطائرة في المطار (فصحى)',
    description: 'تنبيه عاجل من شركة طيران للتوجه نحو بوابة الصعود لإنهاء الفحص.',
    taxonomyCategory: 'legitimate_urgency',
    dialect: 'msa',
    modality: 'text',
    input: {
      text: 'إشعار رحلة عاجل: طائرتكم تقلع بعد 40 دقيقة. يرجى التوجه إلى بوابة الصعود رقم 14 فوراً لإنهاء إجراءات التفتيش الأمني.',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    forbiddenDnaFeatures: ['threat_language'],
    rationale: 'استعجال لوجستي حقيقي ومباشر في بيئة المطار دون أي طلب لبيانات حساسة.',
  },

  // =========================================================================
  // Category 4: Benign Suspicious-Looking Domains
  // =========================================================================
  {
    id: 'RED-010',
    title: 'رابط بوابة نتائج دراسية جامعة صنعاء (.edu.ye)',
    description: 'رابط أكاديمي رسمي متعدد المستويات لنتائج طلاب كلية الهندسة بجامعة صنعاء.',
    taxonomyCategory: 'benign_suspicious_domains',
    dialect: 'msa',
    modality: 'url',
    input: {
      url: 'https://portal.student-records.su.edu.ye/grades/2026/semester2/results',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    rationale: 'نطاق أكاديمي رسمي تابع لليمن (.edu.ye) وإن كان يحتوي على نطاقات فرعية عميقة.',
  },
  {
    id: 'RED-011',
    title: 'رابط خدمة بلدية حكومية إقليمية طويلة المسار (.gov.om)',
    description: 'بوابة إلكترونية رسمية لشؤون السجل المدني والبلديات بسلطنة عمان.',
    taxonomyCategory: 'benign_suspicious_domains',
    dialect: 'msa',
    modality: 'url',
    input: {
      url: 'https://eservices.sub-registry.municipal-affairs.gov.om/public/inquiry-service',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    rationale: 'نطاق حكومي رسمي (.gov.om) لا يجب أن يتأثر بطول المسار أو الشُرَط.',
  },
  {
    id: 'RED-012',
    title: 'رابط واجهة مراقبة حوسبة سحابية أكاديمية (.ac.ae)',
    description: 'رابط قياس ومراقبة للبنية التحتية لمركز حوسبة أكاديمي في الإمارات.',
    taxonomyCategory: 'benign_suspicious_domains',
    dialect: 'mixed_en',
    modality: 'url',
    input: {
      url: 'https://central-api.cloud-monitoring.datacenter.ac.ae/v2/metrics',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    rationale: 'نطاق تعليمي وبحثي موثق (.ac.ae) يستخدم مصطلحات تقنية معقدة لكنها مشروعة.',
  },

  // =========================================================================
  // Category 5: Arabizi Obfuscation (Script Evasion)
  // =========================================================================
  {
    id: 'RED-013',
    title: 'تصيد بنكي بالأرابيزي لسرقة رمز الـ OTP',
    description: 'رسالة احتيال مصرفية مكتوبة بلغة الأرابيزي تطلب إدخال الـ OTP فوراً لتفادي تجميد الحساب.',
    taxonomyCategory: 'arabizi_obfuscation',
    dialect: 'arabizi',
    modality: 'text_url',
    input: {
      text: 'ya 5oy 7sabk t36l 3shan el t7deeth. d5ol hna w 7ot el OTP bsor3a: https://bank-login.top/auth',
      url: 'https://bank-login.top/auth',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'BANK_IMPERSONATION',
    expectedDnaFeatures: ['impersonation', 'otp_request', 'urgency'],
    rationale: 'محاولة التهرب من كواشف الكلمات الدلالية العربية بكتابة الاحتيال بالأرابيزي.',
  },
  {
    id: 'RED-014',
    title: 'جائزة وهمية بالأرابيزي تطلب رقم البطاقة',
    description: 'رسالة ربح جائزة مالية 50 ألف دولار مكتوبة بالأرابيزي لطلب بيانات البطاقة.',
    taxonomyCategory: 'arabizi_obfuscation',
    dialect: 'arabizi',
    modality: 'text_url',
    input: {
      text: 'mbrooook fzt b 50 alf dollar m3 mhrjan el sayef! eb3t esmak w rkm el karta hna: https://prize-claim.xyz',
      url: 'https://prize-claim.xyz',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'FAKE_PRIZE',
    expectedDnaFeatures: ['financial_lure', 'credential_request'],
    rationale: 'احتيال جوائز مكتوب بالأرابيزي يطلب تفاصيل البطاقة المصرفية.',
  },
  {
    id: 'RED-015',
    title: 'احتيال توصيل طرود بالأرابيزي ورسوم غير مدفوعة',
    description: 'إشعار طرد بالأرابيزي يطالب بدفع 15 ريالاً لاستلام الشحنة عبر رابط مريب.',
    taxonomyCategory: 'arabizi_obfuscation',
    dialect: 'arabizi',
    modality: 'text_url',
    input: {
      text: 'sh7ntak wslat bas bagee tdfe3 15 riyal rosoom el twseel d5ol rabet: https://aramex-pay.club',
      url: 'https://aramex-pay.club',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'DELIVERY_SCAM',
    expectedDnaFeatures: ['impersonation', 'suspicious_payment_request'],
    rationale: 'انتحال شركة شحن بأحرف لاتينية وأرقام عربيزي لدفع رسوم وهمية.',
  },

  // =========================================================================
  // Category 6: Unicode Confusables & Tatweel Padding (Character Evasion)
  // =========================================================================
  {
    id: 'RED-016',
    title: 'تصيد بنكي بحروف مطولة عمداً (تطويل/تطعيج الكلمات)',
    description: 'إدراج كشيدة وتطويل داخل الكلمات الحساسة للتهرب من كواشف المطابقة النصية.',
    taxonomyCategory: 'unicode_confusables',
    dialect: 'msa',
    modality: 'text_url',
    input: {
      text: 'عـزيـزي الـعـمـيـل: تـم إيـقـاف بـطـاقـتـك الـمـصـرفـيـة، أرسـل رمـز الـتـحـقـق OـTـP فـوراً لـتـفـادي الـتـجـمـيـد: https://bank-secure.top',
      url: 'https://bank-secure.top',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'ACCOUNT_TAKEOVER',
    expectedDnaFeatures: ['impersonation', 'otp_request', 'threat_language'],
    rationale: 'استخدام التطويل (ـ) لكسر كلمات عزيزي والتحقق وOTP للتهرب من الفلترة.',
  },
  {
    id: 'RED-017',
    title: 'تصيد بفواصل ومسافات صفرية (Zero-Width Space)',
    description: 'حشو أحرف خفية صفرية العرض بين الكلمات لمنع اكتشاف العبارات البنكية الاحتيالية.',
    taxonomyCategory: 'unicode_confusables',
    dialect: 'msa',
    modality: 'text_url',
    input: {
      text: 'تنبيه​​بنكي​​عاجل: تم​​حظر​​حسابك​​المصرفي​​بسبب​​عدم​​التحديث. افتح​​الرابط: https://alrajhi-verify.xyz',
      url: 'https://alrajhi-verify.xyz',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'BANK_IMPERSONATION',
    expectedDnaFeatures: ['impersonation', 'threat_language'],
    rationale: 'إدخال محارف صفرية العرض (U+200B) للتهرب من نماذج المطابقة النمطية.',
  },
  {
    id: 'RED-018',
    title: 'تصيد يخلط محارف كيريلية شبيهة بالعربية واللاتينية (Homoglyphs)',
    description: 'استبدال أحرف عربية ولاتينية بمحارف سيريليك متطابقة شكلاً ولكن مختلفة ترميزاً.',
    taxonomyCategory: 'unicode_confusables',
    dialect: 'msa',
    modality: 'text_url',
    input: {
      text: 'إشعаر مالي: تم إيقаف محفظتك، يرجى تأكيد رقم الهوية وكلمة المرور عبر: https://snb-login.club',
      url: 'https://snb-login.club',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'ACCOUNT_TAKEOVER',
    expectedDnaFeatures: ['credential_request', 'threat_language'],
    rationale: 'استخدام الحرف السيريلي Cyrillic Small Letter A في كلمة إشعار وإيقاف للتمويه.',
  },

  // =========================================================================
  // Category 7: Excessive Emojis & Stylistic Noise (Visual Overload)
  // =========================================================================
  {
    id: 'RED-019',
    title: 'عروض تخفيضات تجارية بلهجة مصرية مليئة بالنيران والإيموجي',
    description: 'نص إعلاني تسويقي لمتجر ملابس حقيقي يستخدم رموزاً كثيفة دون أي احتيال.',
    taxonomyCategory: 'excessive_punctuation_emojis',
    dialect: 'egyptian',
    modality: 'text',
    input: {
      text: '🔥🔥 عرووووض ناااارية بمناسبة الصيف!! 🎉🎉 اشترى قطعتين واحصل على التالتة مجاناً فوراً 🎁🎁 والتوصيل لباب بيتك مجاناً 🛵💨 فروعنا بمدينة نصر والتجمع',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    rationale: 'أسلوب إعلاني صاخب ورموز تعبيرية متكررة لكنه عرض تجاري بريء بدون تصيد.',
  },
  {
    id: 'RED-020',
    title: 'عرض مطعم خليجي بخصم كبير مع إيموجي وعلامات تعجب',
    description: 'إعلان مطعم محلي يدعو للاتصال على الهاتف الأرضي أو الحضور للمطعم.',
    taxonomyCategory: 'excessive_punctuation_emojis',
    dialect: 'gulf',
    modality: 'text',
    input: {
      text: '💥💥 عشاء الجمعة العائلي بخصم 40% في جميع فروعنا!! 🍕🍔 اطلب عن طريق زيارة أقرب فرع واستمتع بأقوى العروض 🌟🌟',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    rationale: 'كثافة علامات الترقيم والإيموجي لا تعني الاحتيال في غياب أهداف سرقة البيانات.',
  },
  {
    id: 'RED-021',
    title: 'تهنئة تخرج جامعي مليئة بإيموجي الاحتفال (فصحى)',
    description: 'منشور تهنئة أكاديمي عفوي مفعم بالرموز والتشجيع.',
    taxonomyCategory: 'excessive_punctuation_emojis',
    dialect: 'msa',
    modality: 'text',
    input: {
      text: '🎉🎉 مبارك التفوق والنجاح لكافة خريجي دفعة 2026!! 🎓🎓 نتمنى لكم مستقبلاً زاهراً ومليئاً بالإنجازات والتميز 🌟👏 نتطلع لرؤيتكم في حفل التكريم القادم.',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    rationale: 'محتوى اجتماعي وإيجابي مليء بالرموز التعبيرية بدون أي مؤشرات أمنية سلبية.',
  },

  // =========================================================================
  // Category 8: Broken / Machine-Translated Arabic (Syntactic Anomaly)
  // =========================================================================
  {
    id: 'RED-022',
    title: 'احتيال توظيف بركاكة لغوية ناتجة عن ترجمة آلية أجنبية',
    description: 'عرض عمل وهمي صادر عن عصابات دولية بمصطلحات عربية غير متناسقة نحوياً.',
    taxonomyCategory: 'broken_arabic',
    dialect: 'broken_arabic',
    modality: 'text_url',
    input: {
      text: 'مرحبا أنا السيدة إليزابيث، شركتنا تجنيد موظف تقييم فنادق بيتك، نحن دفع لك 800 دولار أسبوع عبر عمل بسيط، اضغط رابط التسجيل: https://job-global.top',
      url: 'https://job-global.top',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'JOB_SCAM',
    expectedDnaFeatures: ['financial_lure', 'unexpected_contact'],
    rationale: 'لغة عربية ركيكة ومترجمة آلياً تعد بأرباح خيالية لمهام بسيطة بهدف التصيد.',
  },
  {
    id: 'RED-023',
    title: 'احتيال عملات مشفرة مترجم آلياً من عصابات أجنبية',
    description: 'استدراج للضحية بوعود مضاعفة الأموال عبر منصة تداول وهمية بنصوص آلية مشوهة.',
    taxonomyCategory: 'broken_arabic',
    dialect: 'broken_arabic',
    modality: 'text_url',
    input: {
      text: 'أنا مستثمر أجنبي ديفيد حقق المليون من عملة رقمية، يمكنك بدخول استثمار صغير مائة دولار وربح عشرة أضعاف في ساعات قليلة ادخل هنا: https://invest-crypto.xyz',
      url: 'https://invest-crypto.xyz',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'INVESTMENT_SCAM',
    expectedDnaFeatures: ['financial_lure'],
    rationale: 'نصوص غير سليمة القواعد تحاول إغراء المستخدم بالربح السريع عبر رابط خبيث.',
  },
  {
    id: 'RED-024',
    title: 'احتيال الميراث والرسوم المسبقة بلغة مترجمة متهالكة',
    description: 'ادعاء وجود تركة بملايين الدولارات وطلب رسوم تخليص مسبقة عبر رابط مشبوه.',
    taxonomyCategory: 'broken_arabic',
    dialect: 'broken_arabic',
    modality: 'text_url',
    input: {
      text: 'عزيزي الصديق أنا محامي في لندن موكلي توفي وترك صندوق ملايين، أحتاج شريك أمين في بلدكم لتحويل الأموال، يرجى دفع رسوم شهادة النقل أولاً: https://legal-funds.click',
      url: 'https://legal-funds.click',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'PAYMENT_SCAM',
    expectedDnaFeatures: ['financial_lure', 'suspicious_payment_request'],
    rationale: 'نمط الاحتيال النيجيري الكلاسيكي باللغة المترجمة يطالب بدفع رسوم قبل تحويل التركة.',
  },

  // =========================================================================
  // Category 9: Mixed Arabic / English Concealment (Bilingual Fragmentation)
  // =========================================================================
  {
    id: 'RED-025',
    title: 'تصيد Apple ID يجمع بين إشعار أمني إنجليزي وتوجيه عربي',
    description: 'تجزئة الهجوم بين سياق أمني إنجليزي وتوجيه ضغط باللغة العربية.',
    taxonomyCategory: 'mixed_arabic_english',
    dialect: 'mixed_en',
    modality: 'text_url',
    input: {
      text: 'Security Alert: Your Apple ID has been suspended due to unauthorized access. يرجى تسجيل الدخول وتأكيد الـ password فوراً لتفادي حذف البيانات: https://apple-account-auth.xyz',
      url: 'https://apple-account-auth.xyz',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'ACCOUNT_TAKEOVER',
    expectedDnaFeatures: ['impersonation', 'credential_request', 'threat_language'],
    rationale: 'استغلال التبديل اللغوي لإرباك محركات الفحص التي تعتمد على لغة واحدة فقط.',
  },
  {
    id: 'RED-026',
    title: 'تنبيه بنكي ثنائي اللغة يطلب تحديث KYC عبر رابط تصيد',
    description: 'تنبيه رسمي المظهر يخلط بين مصطلحات الامتثال الإنجليزية والتوجيه العربي.',
    taxonomyCategory: 'mixed_arabic_english',
    dialect: 'mixed_en',
    modality: 'text_url',
    input: {
      text: 'Dear customer, your bank account requires urgent KYC compliance. الرجاء النقر على الرابط وتأكيد بيانات بطاقة الصراف قبل حظر الحساب: https://secure-bank-kyc.top',
      url: 'https://secure-bank-kyc.top',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'BANK_IMPERSONATION',
    expectedDnaFeatures: ['impersonation', 'threat_language', 'credential_request'],
    rationale: 'مزج مصطلح KYC الإنجليزي باللغة العربية المصرفية للحصول على أرقام البطاقة.',
  },
  {
    id: 'RED-027',
    title: 'تصيد محفظة رقمية Metamask بطلب الكلمات المفتاحية (Seed Phrase)',
    description: 'إنذار ثنائي اللغة يدعي وجود ثغرة أمنية في المحفظة ويطلب إدخال الكلمات السرية.',
    taxonomyCategory: 'mixed_arabic_english',
    dialect: 'mixed_en',
    modality: 'text_url',
    input: {
      text: 'Metamask Notice: Critical wallet vulnerability detected. قم بتأكيد الـ recovery seed phrase فوراً عبر الرابط الآمن: https://wallet-verify-node.click',
      url: 'https://wallet-verify-node.click',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'INVESTMENT_SCAM',
    expectedDnaFeatures: ['credential_request', 'threat_language'],
    rationale: 'سرقة عبارة الاسترداد للمحفظة الرقمية عبر دمج المصطلحات التقنية مع التحذير العربي.',
  },

  // =========================================================================
  // Category 10: Misleading Screenshots / Asymmetric Visual Layout
  // =========================================================================
  {
    id: 'RED-028',
    title: 'لقطة شاشة: لافتة إنذار بنكي مصورة تحث على الاتصال برقم مريب',
    description: 'لقطة شاشة تحوي عناصر بصرية حمراء وإنذاراً بتجميد الحساب المصرفي.',
    taxonomyCategory: 'misleading_screenshots',
    dialect: 'msa',
    modality: 'screenshot',
    input: {
      screenshot: {
        mimeType: SCREENSHOT_FIXTURES.SCAM_ARABIC_TEXT.mimeType,
        base64: SCREENSHOT_FIXTURES.SCAM_ARABIC_TEXT.dataUrl,
      },
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'BANK_IMPERSONATION',
    expectedDnaFeatures: ['impersonation', 'threat_language', 'urgency'],
    rationale: 'لقطة شاشة تحوي تصميماً بنكياً مضللاً يطالب بإجراء فوري لتفادي التجميد.',
  },
  {
    id: 'RED-029',
    title: 'لقطة شاشة: واجهة نظام حمراء بريئة تحذر من امتلاء القرص',
    description: 'صورة واجهة داخلية لخادم تستخدم ألواناً حمراء تحذيرية دون وجود أي محتوى احتيالي.',
    taxonomyCategory: 'misleading_screenshots',
    dialect: 'msa',
    modality: 'screenshot',
    input: {
      screenshot: {
        mimeType: SCREENSHOT_FIXTURES.VISUALLY_SUSPICIOUS_BENIGN.mimeType,
        base64: SCREENSHOT_FIXTURES.VISUALLY_SUSPICIOUS_BENIGN.dataUrl,
      },
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    rationale: 'واجهة ذات طابع بصري أحمر مشبوه لكن محتواها بريء يتعلق بمساحة تخزين الخادم.',
  },
  {
    id: 'RED-030',
    title: 'لقطة شاشة: صورة باهتة ومشوشة رديئة الدقة',
    description: 'فحص صورة مشوشة لا يمكن قراءة نصوص منها لقياس حيادية المحرك وعدم تخمين الخطر.',
    taxonomyCategory: 'misleading_screenshots',
    dialect: 'msa',
    modality: 'screenshot',
    input: {
      screenshot: {
        mimeType: SCREENSHOT_FIXTURES.UNREADABLE_LOW_QUALITY.mimeType,
        base64: SCREENSHOT_FIXTURES.UNREADABLE_LOW_QUALITY.dataUrl,
      },
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    rationale: 'يجب أن يتعامل النظام بحذر ودون إطلاق أحكام جازمة بالأمان أو التهديد لغياب النصوص.',
  },

  // =========================================================================
  // Category 11: Visual Brand Resemblance (Color & Icon Spoofing)
  // =========================================================================
  {
    id: 'RED-031',
    title: 'لقطة شاشة: واجهة حصاد رمز التحقق OTP بهوية مؤسسية مزيفة',
    description: 'محاكاة مرئية دقيقة لنافذة إدخال رمز التحقق لاختطاف الحسابات.',
    taxonomyCategory: 'visual_brand_resemblance',
    dialect: 'msa',
    modality: 'screenshot',
    input: {
      screenshot: {
        mimeType: SCREENSHOT_FIXTURES.OTP_HARVESTING_UI.mimeType,
        base64: SCREENSHOT_FIXTURES.OTP_HARVESTING_UI.dataUrl,
      },
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'ACCOUNT_TAKEOVER',
    expectedDnaFeatures: ['otp_request', 'credential_request'],
    rationale: 'عنصر بصري صريح لحصاد رمز التحقق السري تحت مظلة تصميم رسمي.',
  },
  {
    id: 'RED-032',
    title: 'لقطة شاشة: بوابة حكومية مصورة تطلب إدخال رقم الهوية وتاريخ الميلاد',
    description: 'واجهة تصيد بصرية تحاكي البوابات الرسمية لسحب الهويات الشخصية.',
    taxonomyCategory: 'visual_brand_resemblance',
    dialect: 'msa',
    modality: 'screenshot',
    input: {
      screenshot: {
        mimeType: SCREENSHOT_FIXTURES.FAKE_VERIFICATION_PORTAL.mimeType,
        base64: SCREENSHOT_FIXTURES.FAKE_VERIFICATION_PORTAL.dataUrl,
      },
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'GOVERNMENT_IMPERSONATION',
    expectedDnaFeatures: ['impersonation', 'credential_request'],
    rationale: 'محاكاة بصرية للبوابات الوطنية تهدف إلى جمع البيانات الحساسة للمواطنين.',
  },
  {
    id: 'RED-033',
    title: 'لقطة شاشة: ملصق توعوي معتمد يحمل ألواناً مصرفية رسمية بريئة',
    description: 'ملصق توعوي مصرفي يحذر من الاحتيال ويستخدم ألوان البنوك المعتمدة دون خطر.',
    taxonomyCategory: 'visual_brand_resemblance',
    dialect: 'msa',
    modality: 'screenshot',
    input: {
      screenshot: {
        mimeType: SCREENSHOT_FIXTURES.LEGIT_SECURITY_ADVISORY.mimeType,
        base64: SCREENSHOT_FIXTURES.LEGIT_SECURITY_ADVISORY.dataUrl,
      },
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    rationale: 'وجود شعارات أو ألوان البنك في سياق توعوي إيجابي لا يشكل احتيالاً.',
  },

  // =========================================================================
  // Category 12: Multiple / Decoy URLs (URL Splitting)
  // =========================================================================
  {
    id: 'RED-034',
    title: 'رسالة تحوي رابطاً رسمياً كتمويه وبجانبه رابط تصيد بنكي خبيث',
    description: 'إدراج رابط موقع الراجحي الرسمي لطمأنة الضحية مع رابط فرعي خبيث لطلب البيانات.',
    taxonomyCategory: 'multiple_contradictory_urls',
    dialect: 'msa',
    modality: 'text_url',
    input: {
      text: 'عزيزي العميل، حرصاً على أمانك يمكنك مراجعة شروط الخدمة عبر موقعنا الرسمي https://alrajhibank.com.sa ولكن لتحديث بياناتك البنكية الآن افتح: https://alrajhi-update.top/auth',
      url: 'https://alrajhi-update.top/auth',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'BANK_IMPERSONATION',
    expectedDnaFeatures: ['impersonation', 'credential_request'],
    rationale: 'استخدام رابط رسمي كطُعم تمويهي بجانب رابط تصيد احتيالي.',
  },
  {
    id: 'RED-035',
    title: 'رابط حساب تويتر رسمي مرفق مع رابط مسابقة وجائزة وهمية',
    description: 'تمويه الضحية برابط حساب الشركة الموثق ثم توجيهه لرابط سحب مجاني مزور.',
    taxonomyCategory: 'multiple_contradictory_urls',
    dialect: 'gulf',
    modality: 'text_url',
    input: {
      text: 'تابع تغريداتنا الرسمية على تويتر https://twitter.com/stc_ksa ولتفعيل باقة الإنترنت المجانية 100 جيجا ادخل رقم هاتفك هنا: https://stc-gift.click/claim',
      url: 'https://stc-gift.click/claim',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'FAKE_PRIZE',
    expectedDnaFeatures: ['financial_lure', 'impersonation'],
    rationale: 'دمج روابط منصات موثوقة مع روابط جوائز احتيالية لتجاوز الفلاتر الساذجة.',
  },
  {
    id: 'RED-036',
    title: 'رسالة تقنية بريئة تحوي روابط توثيق متعددة',
    description: 'رسالة مطورين تشارك رابطين لمستودع برمجيات وموقع توثيق رسمي.',
    taxonomyCategory: 'multiple_contradictory_urls',
    dialect: 'mixed_en',
    modality: 'text_url',
    input: {
      text: 'للاطلاع على التوثيق الفني للمشروع راجع https://github.com/facebook/react وللحصول على أمثلة الكود تفضل بزيارة https://react.dev في أي وقت.',
      url: 'https://react.dev',
    },
    expectedRiskCategory: 'low',
    expectedScamType: 'UNKNOWN',
    expectedDnaFeatures: [],
    rationale: 'روابط تقنية متعددة مشروعة ومعتمدة ولا تحتوي على أي محتوى مريب.',
  },

  // =========================================================================
  // Category 13: Contradictory Evidence Fusion
  // =========================================================================
  {
    id: 'RED-037',
    title: 'افتتاحية دينية ودية ملحقة بتهديد بنكي عاجل بالتجميد',
    description: 'خلط المشاعر الإيجابية والدعاء بإنذار بنكي صارم بالتجميد خلال 30 دقيقة.',
    taxonomyCategory: 'contradictory_evidence_fusion',
    dialect: 'msa',
    modality: 'text_url',
    input: {
      text: 'السلام عليكم ورحمة الله وبركاته، تقبل الله طاعاتكم وصالح أعمالكم. نود إبلاغكم بأنه سيتم تجميد حسابكم المصرفي نهائياً خلال 30 دقيقة ما لم تحدث بياناتك: https://bank-verify.top',
      url: 'https://bank-verify.top',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'BANK_IMPERSONATION',
    expectedDnaFeatures: ['impersonation', 'threat_language', 'urgency'],
    rationale: 'تناقض واضح بين المشاعر الروحية الهادئة وبين ضغط التهديد المالي الفوري.',
  },
  {
    id: 'RED-038',
    title: 'مخاطبة حكومية رسمية مهذبة تتضمن تحويلاً مالياً لجهة مجهولة',
    description: 'خطاب بأسلوب بروتوكولي مهذب ينتهي بطلب تحويل غرامة مالية لتفادي القبض.',
    taxonomyCategory: 'contradictory_evidence_fusion',
    dialect: 'gulf',
    modality: 'text_url',
    input: {
      text: 'سعادة المحترم: تهديكم الهيئة العامة أطيب التحيات. نفيدكم بوجود غرامة قضائية مستحقة ويجب تحويل 500 ريال فوراً لحساب مجهول لتجنب صدور أمر قبض: https://court-fine.click',
      url: 'https://court-fine.click',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'GOVERNMENT_IMPERSONATION',
    expectedDnaFeatures: ['impersonation', 'threat_language', 'suspicious_payment_request'],
    rationale: 'تناقض بين الصياغة الحكومية الرسمية وبين تحويل مبالغ نقدية لحسابات غير معلنة.',
  },
  {
    id: 'RED-039',
    title: 'تحية عائلية ومشاعر قرابة متبوعة بطلب رمز تحقق (لهجة يمنية)',
    description: 'انتحال صفة قريب يطلب تأكيد كود أمان للدخول إلى الحساب.',
    taxonomyCategory: 'contradictory_evidence_fusion',
    dialect: 'yemeni',
    modality: 'text_url',
    input: {
      text: 'حياك يا ابن العم وجمعة مباركة عليك وعلى الأهل. بالله عليك خش هذا الرابط وسوي تأكيد لرمز التحقق اللي بيوصلك عشان أسترجع حسابي: https://whatsapp-auth.xyz',
      url: 'https://whatsapp-auth.xyz',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'ACCOUNT_TAKEOVER',
    expectedDnaFeatures: ['otp_request', 'impersonation'],
    rationale: 'استغلال صلة القرابة والتحية الودية لتمرير عملية اختطاف الحسابات.',
  },

  // =========================================================================
  // Category 14: Scam Language Without Any URL (Social Directing)
  // =========================================================================
  {
    id: 'RED-040',
    title: 'جائزة نقدية تدعو للاتصال الهاتفي والتوجه للصراف (لهجة يمنية)',
    description: 'احتيال جوائز نقدي لا يحتوي على أي رابط بل يوجه للاتصال والتحويل المالي.',
    taxonomyCategory: 'scam_language_no_url',
    dialect: 'yemeni',
    modality: 'text',
    input: {
      text: 'مبروك فزت معنا بجائزة نقدية 2 مليون ريال يمني في سحب مهرجان الصيف. لاستلام المبلغ توجه لأقرب صراف كريمي وتواصل مع الأستاذ محمد عبر الاتصال بالرقم [PHONE] لتسليم كود الحوالة.',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'FAKE_PRIZE',
    expectedDnaFeatures: ['financial_lure', 'action_pressure'],
    rationale: 'احتيال هندسة اجتماعية خالي من الروابط يعتمد على التوجيه المالي عبر الهاتف.',
  },
  {
    id: 'RED-041',
    title: 'إنذار بإيقاف بطاقة مدى يدعو لمراسلة واتساب هاتفياً (لهجة خليجية)',
    description: 'إشعار تجميد بطاقة مصرفية يطالب بالتواصل عبر الواتساب فوراً دون روابط.',
    taxonomyCategory: 'scam_language_no_url',
    dialect: 'gulf',
    modality: 'text',
    input: {
      text: 'عزيزي العميل، تم إيقاف بطاقة مدى البنكية الخاصة بك لتفادي سرقة رصيدك. يرجى إرسال رسالة واتساب عاجلة إلى مسؤول الحسابات عبر الرقم [PHONE] لإعادة التفعيل.',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'BANK_IMPERSONATION',
    expectedDnaFeatures: ['impersonation', 'threat_language', 'action_pressure'],
    rationale: 'انتحال بنكي بدون روابط يدفع الضحية إلى فخ المحادثة الخاصة عبر واتساب.',
  },
  {
    id: 'RED-042',
    title: 'منحة بنكية وهمية توجه للاتصال بالهاتف فوراً (لهجة مصرية)',
    description: 'ادعاء فوز بمنحة نقدية من البنك المركزي وطلب الاتصال الفوري لاستلام الشيك.',
    taxonomyCategory: 'scam_language_no_url',
    dialect: 'egyptian',
    modality: 'text',
    input: {
      text: 'يا فندم مبروك كسبت معانا منحة مالية 50 ألف جنيه من البنك المركزي. اتصل حالاً على [PHONE] عشان نمليك بيانات استلام الشيك البنكي قبل انتهاء الدوام.',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'FAKE_PRIZE',
    expectedDnaFeatures: ['financial_lure', 'impersonation', 'action_pressure'],
    rationale: 'احتيال جوائز يعتمد كلياً على الاتصال المباشر دون استخدام مواقع إلكترونية.',
  },

  // =========================================================================
  // Category 15: Suspicious URL Inside Legitimate Message (Trojan Messaging)
  // =========================================================================
  {
    id: 'RED-043',
    title: 'تهنئة عيد فطر دافئة ملغمة برابط تصيد خبيث (فصحى)',
    description: 'بطاقة معايدة دينية تحتوي على رابط ينتهي بنطاق احتيالي (.click).',
    taxonomyCategory: 'suspicious_url_in_legitimate_msg',
    dialect: 'msa',
    modality: 'text_url',
    input: {
      text: 'كل عام وأنتم بألف خير بمناسبة عيد الفطر المبارك، أعاده الله عليكم باليمن والبركات. شاهد بطاقة المعايدة المهداة لك باسمك من هنا: https://eid-mubarak.click/card',
      url: 'https://eid-mubarak.click/card',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'SOCIAL_ENGINEERING',
    expectedDnaFeatures: ['unexpected_contact'],
    rationale: 'استغلال المشاعر الاحتفالية لدفع الضحية للضغط على رابط مجهول وسارق للبيانات.',
  },
  {
    id: 'RED-044',
    title: 'تهنئة باليوم الوطني تحتوي على رابط سحب احتيالي (لهجة خليجية)',
    description: 'رسالة وطنية ودية تدعو للدخول في سحب هدية مجانية عبر نطاق مشبوه.',
    taxonomyCategory: 'suspicious_url_in_legitimate_msg',
    dialect: 'gulf',
    modality: 'text_url',
    input: {
      text: 'دام عزك يا وطن! بمناسبة اليوم الوطني المجيد شارك في السحب الوطني الكبير واحصل على هدية مجانية فوراً: https://saudi-national-day.top/gift',
      url: 'https://saudi-national-day.top/gift',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'FAKE_PRIZE',
    expectedDnaFeatures: ['financial_lure'],
    rationale: 'دس رابط تصيد داخل تهنئة وطنية بهدف استدراج المستخدمين.',
  },
  {
    id: 'RED-045',
    title: 'تبريكات بشهر رمضان الكريم ملحومة برابط باقة مجانية (لهجة يمنية)',
    description: 'رسالة رمضانية روحية تعد برصيد إنترنت مجاني عبر رابط مجهول.',
    taxonomyCategory: 'suspicious_url_in_legitimate_msg',
    dialect: 'yemeni',
    modality: 'text_url',
    input: {
      text: 'مبارك عليكم الشهر الفضيل يا غالي، جعلنا الله وإياكم من صوامه وقوامه. افتح الرابط واستلم باقة رمضان المجانية من شركة الاتصالات: https://yemen-net-ramadan.xyz/claim',
      url: 'https://yemen-net-ramadan.xyz/claim',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'FAKE_PRIZE',
    expectedDnaFeatures: ['financial_lure'],
    rationale: 'استغلال المناسبات الدينية في اليمن لترويج روابط وهمية تسحب البيانات.',
  },

  // =========================================================================
  // Category 16: Long Distracting Text Containing Malicious Instructions
  // =========================================================================
  {
    id: 'RED-046',
    title: 'مقال تحليلي اقتصادي مطول يخفي في نهايته رابط تحديث بنكي عاجل',
    description: 'نص إخباري طويل يغرق المصنف في مصطلحات اقتصادية محايدة مع دس رابط تصيد بنكي.',
    taxonomyCategory: 'long_distracting_text',
    dialect: 'msa',
    modality: 'text_url',
    input: {
      text: 'أظهرت المؤشرات الاقتصادية الصادرة عن البنك المركزي صباح اليوم استقراراً ملحوظاً في أسعار الصرف ومعدلات التضخم السنوية، حيث أشارت التقارير إلى أن السياسات النقدية المتبعة ساهمت في تعزيز الاحتياطي النقدي ودعم العملة المحلية في مواجهة التحديات الإقليمية والدولية. وأكدت المصادر المصرفية أن القطاع التجاري يشهد نمواً تدريجياً في حجم التعاملات اليومية، كما دعت المؤسسات المالية كافة المستثمرين إلى تنويع محافظهم الاستثمارية بما يتماشى مع أهداف التنمية الاقتصادية الشاملة. وفي هذا السياق، يرجى من جميع عملاء البنوك المسجلين الدخول إلى الرابط التالي لتحديث بيانات الهوية فوراً لتجنب تجميد الحسابات https://central-bank-update.top/login وذلك قبل نهاية يوم العمل المصرفي الحالي.',
      url: 'https://central-bank-update.top/login',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'BANK_IMPERSONATION',
    expectedDnaFeatures: ['impersonation', 'credential_request', 'threat_language'],
    rationale: 'إغراق النموذج بنصوص محايدة وطويلة لمحاولة تخفيف كثافة إشارات التهديد وإخفاء الرابط الخبيث.',
  },
  {
    id: 'RED-047',
    title: 'مقال علمي عن الذكاء الاصطناعي يخفي رابط استثمار وهمي عالي الربح',
    description: 'نص أكاديمي موسع يختتم بدعوة لتحويل أموال إلى محفظة استثمارية مشبوهة.',
    taxonomyCategory: 'long_distracting_text',
    dialect: 'msa',
    modality: 'text_url',
    input: {
      text: 'شهدت تقنيات الذكاء الاصطناعي وتعلم الآلة تطورات هائلة خلال السنوات الأخيرة، حيث أصبحت الخوارزميات قادرة على معالجة البيانات الضخمة بدقة وسرعة غير مسبوقة. وتعتمد النظم الحديثة على شبكات عصبية عميقة تحاكي طريقة عمل الدماغ البشري، مما ساعد في تحسين خدمات الرعاية الصحية والتشخيص الطبي وتوقع الكوارث الطبيعية. غير أن الاستخدام المتزايد لهذه التطبيقات يفرض تحديات أخلاقية وتنظيمية تتعلق بالخصوصية وأمن المعلومات. إذا كنت ترغب في استثمار أموالك في أسهم الذكاء الاصطناعي بربح مضمون 300% أسبوعياً قم بتحويل رصيدك الآن إلى المحفظة الرقمية عبر الرابط https://ai-invest-profit.xyz للاستفادة من هذه الفرصة الذهبية قبل إغلاق الاكتتاب.',
      url: 'https://ai-invest-profit.xyz',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'INVESTMENT_SCAM',
    expectedDnaFeatures: ['financial_lure', 'suspicious_payment_request'],
    rationale: 'تشتيت الانتباه بمحتوى تقني تثقيفي محايد ثم تمرير احتيال بونزي عالي العائد.',
  },
  {
    id: 'RED-048',
    title: 'تعميم إداري لموظفي شركة يحتوي على طلب إدخال كلمة مرور بريد داخلي',
    description: 'رسالة إدارية رسمية عن صيانة المبنى تنتهي بطلب تسجيل الدخول وسرقة الـ OTP.',
    taxonomyCategory: 'long_distracting_text',
    dialect: 'msa',
    modality: 'text_url',
    input: {
      text: 'تعميم داخلي إلى كافة الموظفين والعاملين في مختلف الأقسام والإدارات الفنية والإدارية: نود إحاطتكم علماً بأنه سيتم إجراء أعمال صيانة دورية مجدولة لشبكات الحاسب الآلي وأنظمة التكييف المركزي والمصاعد خلال عطلة نهاية الأسبوع القادمة، وذلك لضمان كفاءة بيئة العمل وسلامة المنشأة. يرجى من الجميع التأكد من إيقاف تشغيل أجهزة الحاسوب الشخصية وفصل الأجهزة الكهربائية قبل مغادرة مكاتبهم يوم الخميس. علماً بأنه يتوجب على كل موظف إدخال كلمة مرور بريده الإلكتروني والـ OTP عبر الرابط https://portal-internal-auth.click لتأكيد استمرار صلاحية الدخول للشبكة.',
      url: 'https://portal-internal-auth.click',
    },
    expectedRiskCategory: 'high',
    expectedScamType: 'ACCOUNT_TAKEOVER',
    expectedDnaFeatures: ['credential_request', 'otp_request'],
    rationale: 'حشو التعليمات الخبيثة لسرقة كلمات المرور في نهاية تعميم روتيني لصيانة المنشآت.',
  },
];
