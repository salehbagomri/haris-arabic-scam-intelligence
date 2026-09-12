/**
 * HARIS (حارس) — Evaluation Screenshot Fixtures
 *
 * Synthetic, self-contained screenshot fixtures for evaluating visual extraction,
 * fallback behavior, and multimodal intelligence without using real private screenshots.
 */

export interface ScreenshotFixture {
  id: string;
  name: string;
  mimeType: string;
  dataUrl: string;
  simulatedVisualDescription: string;
}

// Minimal valid PNG fixtures (RFC 2083 compliant)
const BASE_PNG_RED = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const BASE_PNG_GREEN = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPj/HwADBwIAMCbhyQAAAABJRU5ErkJggg==';
const BASE_PNG_BLUE = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';
const BASE_PNG_YELLOW = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PchI7wAAAABJRU5ErkJggg==';
const BASE_PNG_GRAY = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mPc9+bTfwAIGQNz5lS2/wAAAABJRU5ErkJggg==';

export const SCREENSHOT_FIXTURES: Record<string, ScreenshotFixture> = {
  // 1. Visible Arabic Scam Text
  SCAM_ARABIC_TEXT: {
    id: 'FIXTURE_SCAM_ARABIC_TEXT',
    name: 'تنبيه بنكي احتيالي مصور',
    mimeType: 'image/png',
    dataUrl: BASE_PNG_RED,
    simulatedVisualDescription: 'رسالة نصية معروضة على شاشة هاتف تفيد بتجميد الحساب البنكي والمطالبة بالاتصال بالرقم المرفق فوراً.',
  },

  // 2. Visible OTP Harvesting Prompt
  OTP_HARVESTING_UI: {
    id: 'FIXTURE_OTP_HARVESTING_UI',
    name: 'نافذة منبثقة تطلب رمز OTP',
    mimeType: 'image/png',
    dataUrl: BASE_PNG_RED,
    simulatedVisualDescription: 'واجهة تطبيق مزيفة تطلب إدخال رمز التحقق لمرة واحدة OTP المرسل إلى الهاتف لتفعيل الخدمة.',
  },

  // 3. Fake Verification UI / Phishing Portal
  FAKE_VERIFICATION_PORTAL: {
    id: 'FIXTURE_FAKE_VERIFICATION_PORTAL',
    name: 'بوابة توثيق مزيفة لجهة رسمية',
    mimeType: 'image/png',
    dataUrl: BASE_PNG_YELLOW,
    simulatedVisualDescription: 'صفحة ويب تحاكي بوابة حكومية رسمية مع شعار مقلد ونموذج يطلب رقم الهوية وتاريخ الميلاد.',
  },

  // 4. Suspicious Payment Prompt
  SUSPICIOUS_PAYMENT_PROMPT: {
    id: 'FIXTURE_SUSPICIOUS_PAYMENT_PROMPT',
    name: 'شاشة دفع مشبوهة بمحفظة إلكترونية',
    mimeType: 'image/png',
    dataUrl: BASE_PNG_RED,
    simulatedVisualDescription: 'واجهة محفظة إلكترونية غير رسمية تطالب بتحويل فوري لرسوم إدارية غير مبررة عبر حوالة سريعة.',
  },

  // 5. Legitimate Security Advisory
  LEGIT_SECURITY_ADVISORY: {
    id: 'FIXTURE_LEGIT_SECURITY_ADVISORY',
    name: 'تحذير أمني رسمي صادر من بنك معتمد',
    mimeType: 'image/png',
    dataUrl: BASE_PNG_GREEN,
    simulatedVisualDescription: 'ملصق توعوي معتمد يحمل شعار رسمي يحذر العملاء من مشاركة رمز OTP أو الضغط على الروابط المجهولة.',
  },

  // 6. Visually Suspicious but Benign UI
  VISUALLY_SUSPICIOUS_BENIGN: {
    id: 'FIXTURE_VISUALLY_SUSPICIOUS_BENIGN',
    name: 'واجهة نظام ذات ألوان تحذيرية حمراء ولكنها إشعار خادم داخلي',
    mimeType: 'image/png',
    dataUrl: BASE_PNG_BLUE,
    simulatedVisualDescription: 'لوحة معلومات تقنية تستخدم شارات حمراء للإشارة إلى انخفاض مساحة التخزين في الخادم الداخلي.',
  },

  // 7. Unreadable / Degraded Screenshot
  UNREADABLE_LOW_QUALITY: {
    id: 'FIXTURE_UNREADABLE_LOW_QUALITY',
    name: 'لقطة شاشة غير واضحة ومشوشة تماماً',
    mimeType: 'image/png',
    dataUrl: BASE_PNG_GRAY,
    simulatedVisualDescription: 'صورة رمادية باهتة لا تحتوي على نصوص مقروءة أو عناصر بصرية واضحة.',
  },
};
