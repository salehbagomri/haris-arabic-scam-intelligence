/**
 * HARIS (حارس) — Synthetic Screenshot Fixture Generator (Development-Only)
 *
 * NOTE: This script is for development/authoring time only to deterministically
 * generate authentic, multi-kilobyte synthetic PNG screenshot fixtures with sharp.
 * The production runtime and evaluation runner do NOT execute this script;
 * they strictly consume the self-contained base64 data URLs embedded in
 * evaluation/fixtures/screenshots.ts.
 */

import sharp from 'sharp';
import * as fs from 'fs';
import * as path from 'path';

interface FixtureDef {
  key: string;
  id: string;
  name: string;
  mimeType: string;
  svg: string;
  description: string;
}

const FIXTURES: FixtureDef[] = [
  // 1. Visible Arabic Scam Text
  {
    key: 'SCAM_ARABIC_TEXT',
    id: 'FIXTURE_SCAM_ARABIC_TEXT',
    name: 'تنبيه بنكي احتيالي مصور',
    mimeType: 'image/png',
    description: 'رسالة نصية معروضة على شاشة هاتف تفيد بتجميد الحساب البنكي والمطالبة بالاتصال بالرقم المرفق فوراً.',
    svg: `
    <svg width="600" height="900" viewBox="0 0 600 900" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#090d16"/>
      <!-- Phone Frame -->
      <rect x="30" y="30" width="540" height="840" rx="36" fill="#111827" stroke="#1f2937" stroke-width="4"/>
      <!-- Header Bar -->
      <rect x="30" y="30" width="540" height="80" rx="36" fill="#1f2937"/>
      <circle cx="70" cy="70" r="16" fill="#ef4444"/>
      <text x="300" y="76" fill="#f3f4f6" font-size="20" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">تنبيه بنكي عاجل</text>
      <!-- Red Alert Banner -->
      <rect x="60" y="140" width="480" height="120" rx="16" fill="#7f1d1d" stroke="#ef4444" stroke-width="2"/>
      <text x="300" y="190" fill="#fecaca" font-size="26" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">⚠️ إيقاف الحساب المصرفي</text>
      <text x="300" y="230" fill="#fca5a5" font-size="16" font-family="Arial, sans-serif" text-anchor="middle">تم تجميد حسابك مؤقتاً لمخالفة التعليمات الأمنية</text>
      <!-- Message Card -->
      <rect x="60" y="290" width="480" height="340" rx="16" fill="#1e293b" stroke="#334155" stroke-width="1.5"/>
      <text x="500" y="340" fill="#e2e8f0" font-size="18" font-family="Arial, sans-serif" text-anchor="end">عزيزي العميل:</text>
      <text x="500" y="380" fill="#cbd5e1" font-size="16" font-family="Arial, sans-serif" text-anchor="end">نحيطكم علماً بأنه تم إيقاف بطاقتكم المصرفية</text>
      <text x="500" y="415" fill="#cbd5e1" font-size="16" font-family="Arial, sans-serif" text-anchor="end">وحسابكم الجاري لتفادي الاحتيال والعمليات المشبوهة.</text>
      <text x="500" y="460" fill="#e2e8f0" font-size="16" font-family="Arial, sans-serif" font-weight="bold" text-anchor="end">لتنشيط الحساب فوراً وتفادي الإلغاء النهائي:</text>
      <text x="500" y="500" fill="#38bdf8" font-size="16" font-family="Arial, sans-serif" text-anchor="end">يرجى الاتصال بمسؤول التحديث عبر الرقم [PHONE]</text>
      <text x="500" y="540" fill="#f87171" font-size="15" font-family="Arial, sans-serif" text-anchor="end">أو تأكيد بياناتك خلال ساعتين من تاريخ الرسالة.</text>
      <!-- Urgent Action Button -->
      <rect x="100" y="670" width="400" height="64" rx="32" fill="#dc2626"/>
      <text x="300" y="710" fill="#ffffff" font-size="20" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">تحديث البيانات واستعادة الحساب</text>
      <!-- Footer note -->
      <text x="300" y="790" fill="#64748b" font-size="14" font-family="Arial, sans-serif" text-anchor="middle">قسم أمن العمليات المصرفية المركزية</text>
    </svg>
    `,
  },

  // 2. Visible OTP Harvesting Prompt
  {
    key: 'OTP_HARVESTING_UI',
    id: 'FIXTURE_OTP_HARVESTING_UI',
    name: 'نافذة منبثقة تطلب رمز OTP',
    mimeType: 'image/png',
    description: 'واجهة تطبيق مزيفة تطلب إدخال رمز التحقق لمرة واحدة OTP لتأكيد العملية.',
    svg: `
    <svg width="600" height="900" viewBox="0 0 600 900" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#0a0f1d"/>
      <!-- Background Blurry Modal Overlay -->
      <rect x="40" y="80" width="520" height="740" rx="28" fill="#0f172a" stroke="#1e293b" stroke-width="2"/>
      <!-- Security Icon Header -->
      <circle cx="300" cy="180" r="44" fill="#ef4444" opacity="0.15"/>
      <circle cx="300" cy="180" r="30" fill="#dc2626"/>
      <text x="300" y="190" fill="#ffffff" font-size="28" font-family="Arial, sans-serif" text-anchor="middle">🔒</text>
      <!-- Modal Title -->
      <text x="300" y="260" fill="#f8fafc" font-size="24" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">رمز التحقق لمرة واحدة (OTP)</text>
      <text x="300" y="300" fill="#94a3b8" font-size="16" font-family="Arial, sans-serif" text-anchor="middle">أدخل الرمز السري المكون من 6 أرقام المرسل إلى هاتفك</text>
      <text x="300" y="325" fill="#64748b" font-size="14" font-family="Arial, sans-serif" text-anchor="middle">لتأكيد العملية المالية واستكمال الدخول</text>
      <!-- 6 Digit Input Boxes -->
      <g transform="translate(60, 370)">
        <rect x="0" y="0" width="65" height="75" rx="12" fill="#1e293b" stroke="#3b82f6" stroke-width="2"/>
        <text x="32" y="48" fill="#f8fafc" font-size="32" font-family="Arial, sans-serif" text-anchor="middle">•</text>
        <rect x="80" y="0" width="65" height="75" rx="12" fill="#1e293b" stroke="#3b82f6" stroke-width="2"/>
        <text x="112" y="48" fill="#f8fafc" font-size="32" font-family="Arial, sans-serif" text-anchor="middle">•</text>
        <rect x="160" y="0" width="65" height="75" rx="12" fill="#1e293b" stroke="#475569" stroke-width="1.5"/>
        <rect x="240" y="0" width="65" height="75" rx="12" fill="#1e293b" stroke="#475569" stroke-width="1.5"/>
        <rect x="320" y="0" width="65" height="75" rx="12" fill="#1e293b" stroke="#475569" stroke-width="1.5"/>
        <rect x="400" y="0" width="65" height="75" rx="12" fill="#1e293b" stroke="#475569" stroke-width="1.5"/>
      </g>
      <!-- Countdown Timer -->
      <text x="300" y="490" fill="#f59e0b" font-size="16" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">⏱️ ينتهي الرمز خلال 00:45 ثانية</text>
      <!-- Warning Note -->
      <rect x="80" y="530" width="440" height="70" rx="12" fill="#450a0a" stroke="#991b1b" stroke-width="1"/>
      <text x="300" y="560" fill="#fca5a5" font-size="14" font-family="Arial, sans-serif" text-anchor="middle">⚠️ عدم إدخال الرمز سيؤدي إلى حظر الحساب فوراً</text>
      <text x="300" y="582" fill="#f87171" font-size="13" font-family="Arial, sans-serif" text-anchor="middle">تأكيد تسجيل الدخول من جهاز غير معروف</text>
      <!-- Confirm Button -->
      <rect x="80" y="640" width="440" height="60" rx="16" fill="#ef4444"/>
      <text x="300" y="677" fill="#ffffff" font-size="18" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">تأكيد الرمز واستكمال العملية</text>
      <text x="300" y="740" fill="#64748b" font-size="14" font-family="Arial, sans-serif" text-anchor="middle">إعادة إرسال رمز جديد</text>
    </svg>
    `,
  },

  // 3. Fake Verification UI / Phishing Portal
  {
    key: 'FAKE_VERIFICATION_PORTAL',
    id: 'FIXTURE_FAKE_VERIFICATION_PORTAL',
    name: 'بوابة توثيق مزيفة لجهة رسمية',
    mimeType: 'image/png',
    description: 'صفحة ويب تحاكي بوابة حكومية رسمية مع نموذج يطلب رقم الهوية وتاريخ الميلاد.',
    svg: `
    <svg width="600" height="900" viewBox="0 0 600 900" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#f8fafc"/>
      <!-- Top Green Official Emulation Bar -->
      <rect width="100%" height="110" fill="#047857"/>
      <text x="300" y="65" fill="#ffffff" font-size="22" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">بوابة الخدمات والتوثيق الإلكتروني الموحدة</text>
      <text x="300" y="92" fill="#a7f3d0" font-size="14" font-family="Arial, sans-serif" text-anchor="middle">المنصة الوطنية لتحديث وتفعيل الحسابات</text>
      <!-- Form Container -->
      <rect x="40" y="140" width="520" height="690" rx="16" fill="#ffffff" stroke="#e2e8f0" stroke-width="2"/>
      <text x="520" y="190" fill="#0f172a" font-size="20" font-family="Arial, sans-serif" font-weight="bold" text-anchor="end">يرجى إدخال بيانات التحقق المطلوبة:</text>
      <!-- Input 1: National ID -->
      <text x="520" y="245" fill="#334155" font-size="15" font-family="Arial, sans-serif" text-anchor="end">رقم الهوية الوطنية / الإقامة:</text>
      <rect x="80" y="260" width="440" height="52" rx="8" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.5"/>
      <text x="500" y="292" fill="#94a3b8" font-size="14" font-family="Arial, sans-serif" text-anchor="end">أدخل رقم الهوية المكون من 10 أرقام</text>
      <!-- Input 2: Bank Card Number -->
      <text x="520" y="345" fill="#334155" font-size="15" font-family="Arial, sans-serif" text-anchor="end">رقم البطاقة المصرفية (مدى / فيزا):</text>
      <rect x="80" y="360" width="440" height="52" rx="8" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.5"/>
      <text x="500" y="392" fill="#94a3b8" font-size="14" font-family="Arial, sans-serif" text-anchor="end">•••• •••• •••• ••••</text>
      <!-- Input 3: PIN / Password -->
      <text x="520" y="445" fill="#334155" font-size="15" font-family="Arial, sans-serif" text-anchor="end">الرقم السري للبطاقة (PIN):</text>
      <rect x="80" y="460" width="440" height="52" rx="8" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.5"/>
      <text x="500" y="492" fill="#94a3b8" font-size="14" font-family="Arial, sans-serif" text-anchor="end">••••</text>
      <!-- Input 4: Phone -->
      <text x="520" y="545" fill="#334155" font-size="15" font-family="Arial, sans-serif" text-anchor="end">رقم الهاتف المسجل:</text>
      <rect x="80" y="560" width="440" height="52" rx="8" fill="#f8fafc" stroke="#cbd5e1" stroke-width="1.5"/>
      <text x="500" y="592" fill="#94a3b8" font-size="14" font-family="Arial, sans-serif" text-anchor="end">[PHONE]</text>
      <!-- Urgency warning -->
      <text x="300" y="650" fill="#dc2626" font-size="14" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">⚠️ تنبيه: يرجى التوثيق الفوري قبل حظر الخدمات تلقائياً</text>
      <!-- Submit Button -->
      <rect x="80" y="680" width="440" height="58" rx="10" fill="#047857"/>
      <text x="300" y="716" fill="#ffffff" font-size="18" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">توثيق البيانات ومتابعة الدخول</text>
      <!-- Lock and Security -->
      <text x="300" y="780" fill="#64748b" font-size="13" font-family="Arial, sans-serif" text-anchor="middle">🔒 اتصال مشفر بنظام الأمان الحكومي الموحد</text>
    </svg>
    `,
  },

  // 4. Suspicious Payment Prompt
  {
    key: 'SUSPICIOUS_PAYMENT_PROMPT',
    id: 'FIXTURE_SUSPICIOUS_PAYMENT_PROMPT',
    name: 'شاشة دفع مشبوهة بمحفظة إلكترونية',
    mimeType: 'image/png',
    description: 'واجهة محفظة إلكترونية غير رسمية تطالب بتحويل فوري لرسوم إدارية غير مبررة.',
    svg: `
    <svg width="600" height="900" viewBox="0 0 600 900" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#0b1329"/>
      <!-- Header Card -->
      <rect x="40" y="40" width="520" height="120" rx="20" fill="#1e1b4b" stroke="#312e81" stroke-width="1.5"/>
      <text x="300" y="90" fill="#c7d2fe" font-size="22" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">طلب سداد فوري - محفظة ون كاش / فلوسك</text>
      <text x="300" y="125" fill="#818cf8" font-size="14" font-family="Arial, sans-serif" text-anchor="middle">تحويل إلكتروني مباشر غير قابل للإلغاء</text>
      <!-- Amount Box -->
      <rect x="60" y="190" width="480" height="150" rx="16" fill="#1e293b" stroke="#4338ca" stroke-width="2"/>
      <text x="300" y="240" fill="#94a3b8" font-size="16" font-family="Arial, sans-serif" text-anchor="middle">المبلغ المطلوب سداده فوراً:</text>
      <text x="300" y="295" fill="#38bdf8" font-size="36" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">15,000 ريال يمني</text>
      <!-- Payment Details Box -->
      <rect x="60" y="370" width="480" height="260" rx="16" fill="#1e293b" stroke="#334155" stroke-width="1.5"/>
      <text x="500" y="415" fill="#e2e8f0" font-size="16" font-family="Arial, sans-serif" text-anchor="end">بيانات التحويل:</text>
      <text x="500" y="455" fill="#cbd5e1" font-size="15" font-family="Arial, sans-serif" text-anchor="end">نوع المعاملة: رسوم إدارية غير مستردة لفتح الحساب المعلق</text>
      <text x="500" y="495" fill="#cbd5e1" font-size="15" font-family="Arial, sans-serif" text-anchor="end">المحفظة المستلمة: [ACCOUNT_ID]</text>
      <text x="500" y="535" fill="#cbd5e1" font-size="15" font-family="Arial, sans-serif" text-anchor="end">المهلة المتبقية: 15 دقيقة قبل إلغاء الحوالة</text>
      <text x="500" y="580" fill="#f87171" font-size="14" font-family="Arial, sans-serif" text-anchor="end">⚠️ تنبيه: لا يتم تحرير الحوالة الواردة إلا بعد السداد المسبق.</text>
      <!-- Pay Button -->
      <rect x="60" y="660" width="480" height="64" rx="32" fill="#4f46e5"/>
      <text x="300" y="700" fill="#ffffff" font-size="20" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">تأكيد الدفع والتحويل الآن</text>
      <!-- Security warning -->
      <text x="300" y="770" fill="#64748b" font-size="13" font-family="Arial, sans-serif" text-anchor="middle">معاملة سريعة ومحمية عبر نظام الدفع المحلي</text>
    </svg>
    `,
  },

  // 5. Legitimate Security Advisory
  {
    key: 'LEGIT_SECURITY_ADVISORY',
    id: 'FIXTURE_LEGIT_SECURITY_ADVISORY',
    name: 'تحذير أمني رسمي صادر من بنك معتمد',
    mimeType: 'image/png',
    description: 'ملصق توعوي معتمد يحذر العملاء من مشاركة رمز OTP أو الضغط على الروابط المجهولة.',
    svg: `
    <svg width="600" height="900" viewBox="0 0 600 900" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#f0fdf4"/>
      <!-- Header Banner -->
      <rect width="100%" height="130" fill="#15803d"/>
      <text x="300" y="70" fill="#ffffff" font-size="26" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">🛡️ تنبيه أمني وتوعوي رسمي</text>
      <text x="300" y="105" fill="#bbf7d0" font-size="16" font-family="Arial, sans-serif" text-anchor="middle">إدارة الأمن السيبراني وحماية العملاء</text>
      <!-- Card Container -->
      <rect x="40" y="160" width="520" height="680" rx="20" fill="#ffffff" stroke="#bbf7d0" stroke-width="2"/>
      <circle cx="300" cy="240" r="45" fill="#dcfce7"/>
      <text x="300" y="252" fill="#16a34a" font-size="36" font-family="Arial, sans-serif" text-anchor="middle">🔒</text>
      <!-- Negation statement -->
      <text x="300" y="320" fill="#166534" font-size="22" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">المصرف لن يطلب منك إطلاقاً:</text>
      <rect x="60" y="350" width="480" height="55" rx="10" fill="#fef2f2" stroke="#fecaca" stroke-width="1"/>
      <text x="510" y="384" fill="#991b1b" font-size="16" font-family="Arial, sans-serif" font-weight="bold" text-anchor="end">❌ رمز التحقق لمرة واحدة (OTP)</text>
      <rect x="60" y="420" width="480" height="55" rx="10" fill="#fef2f2" stroke="#fecaca" stroke-width="1"/>
      <text x="510" y="454" fill="#991b1b" font-size="16" font-family="Arial, sans-serif" font-weight="bold" text-anchor="end">❌ كلمة المرور أو الرقم السري للبطاقة (PIN)</text>
      <rect x="60" y="490" width="480" height="55" rx="10" fill="#fef2f2" stroke="#fecaca" stroke-width="1"/>
      <text x="510" y="524" fill="#991b1b" font-size="16" font-family="Arial, sans-serif" font-weight="bold" text-anchor="end">❌ الضغط على روابط مجهولة لتحديث البيانات</text>
      <!-- Guidance -->
      <text x="510" y="585" fill="#334155" font-size="16" font-family="Arial, sans-serif" text-anchor="end">إرشادات الأمان الهامة:</text>
      <text x="510" y="618" fill="#475569" font-size="14" font-family="Arial, sans-serif" text-anchor="end">• حافظ دائماً على سرية بياناتك الشخصية والمصرفية.</text>
      <text x="510" y="648" fill="#475569" font-size="14" font-family="Arial, sans-serif" text-anchor="end">• في حال الاشتباه أو وصول رسالة مريبة، تواصل فوراً مع القنوات الرسمية.</text>
      <text x="510" y="678" fill="#475569" font-size="14" font-family="Arial, sans-serif" text-anchor="end">• قم بالإبلاغ عبر الرقم المعتمد في ظهر بطاقتك البنكية.</text>
      <!-- Verified Badge -->
      <rect x="150" y="740" width="300" height="48" rx="24" fill="#16a34a"/>
      <text x="300" y="770" fill="#ffffff" font-size="16" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">معاً لمكافحة الاحتيال المالي ✓</text>
    </svg>
    `,
  },

  // 6. Visually Suspicious but Benign UI
  {
    key: 'VISUALLY_SUSPICIOUS_BENIGN',
    id: 'FIXTURE_VISUALLY_SUSPICIOUS_BENIGN',
    name: 'واجهة نظام ذات ألوان تحذيرية حمراء ولكنها إشعار خادم داخلي',
    mimeType: 'image/png',
    description: 'لوحة معلومات تقنية تستخدم شارات حمراء للإشارة إلى انخفاض مساحة التخزين في الخادم الداخلي.',
    svg: `
    <svg width="600" height="900" viewBox="0 0 600 900" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#0f172a"/>
      <!-- Top Red Status Banner (Looks Alarming Visually) -->
      <rect width="100%" height="90" fill="#991b1b"/>
      <text x="300" y="55" fill="#ffffff" font-size="22" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">🚨 ALERT: SERVER STORAGE THRESHOLD EXCEEDED</text>
      <!-- Subheader -->
      <rect x="30" y="120" width="540" height="740" rx="16" fill="#1e293b" stroke="#334155" stroke-width="2"/>
      <text x="300" y="165" fill="#f8fafc" font-size="20" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">لوحة مراقبة الخوادم الداخلية (نظام تشغيلي داخلي)</text>
      <!-- Alarm Box -->
      <rect x="50" y="200" width="500" height="180" rx="12" fill="#450a0a" stroke="#dc2626" stroke-width="2"/>
      <text x="300" y="245" fill="#fca5a5" font-size="22" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">تحذير انخفاض مساحة التخزين على القرص الصلب D:/</text>
      <text x="300" y="285" fill="#f87171" font-size="16" font-family="Arial, sans-serif" text-anchor="middle">نسبة الاستخدام الحالية: 87.4% (المتبقي: 12.6 GB فقط)</text>
      <text x="300" y="325" fill="#cbd5e1" font-size="14" font-family="Arial, sans-serif" text-anchor="middle">يجب أرشفة ملفات السجلات القديمة من قبل فريق البنية التحتية</text>
      <text x="300" y="355" fill="#4ade80" font-size="14" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">✓ لا يوجد أي اختراق أمني أو تهديد سيبراني على النظام</text>
      <!-- Technical Metrics Table -->
      <g transform="translate(60, 420)">
        <rect x="0" y="0" width="480" height="45" rx="8" fill="#334155"/>
        <text x="460" y="28" fill="#e2e8f0" font-size="15" font-family="Arial, sans-serif" text-anchor="end">معلومات الخادم: Production Node #04</text>
        <rect x="0" y="55" width="480" height="45" rx="8" fill="#1e293b"/>
        <text x="460" y="83" fill="#94a3b8" font-size="14" font-family="Arial, sans-serif" text-anchor="end">الحالة الأمنية: سليم ومحدث (All Patches Applied)</text>
        <rect x="0" y="110" width="480" height="45" rx="8" fill="#334155"/>
        <text x="460" y="138" fill="#94a3b8" font-size="14" font-family="Arial, sans-serif" text-anchor="end">استهلاك المعالج: 14% | استهلاك الذاكرة: 42%</text>
      </g>
      <!-- Routine Admin Action Button -->
      <rect x="100" y="650" width="400" height="54" rx="12" fill="#2563eb"/>
      <text x="300" y="684" fill="#ffffff" font-size="17" font-family="Arial, sans-serif" font-weight="bold" text-anchor="middle">تشغيل أداة تفريغ السجلات الروتينية (Log Purge)</text>
      <text x="300" y="740" fill="#64748b" font-size="13" font-family="Arial, sans-serif" text-anchor="middle">Internal Enterprise Monitoring Console v4.2</text>
    </svg>
    `,
  },

  // 7. Unreadable / Degraded Screenshot
  {
    key: 'UNREADABLE_LOW_QUALITY',
    id: 'FIXTURE_UNREADABLE_LOW_QUALITY',
    name: 'لقطة شاشة غير واضحة ومشوشة تماماً',
    mimeType: 'image/png',
    description: 'صورة رمادية باهتة لا تحتوي على نصوص مقروءة أو عناصر بصرية واضحة.',
    svg: `
    <svg width="600" height="900" viewBox="0 0 600 900" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <filter id="extremeBlur">
          <feGaussianBlur stdDeviation="35" />
          <feTurbulence type="fractalNoise" baseFrequency="0.08" numOctaves="4" result="noise" />
          <feDisplacementMap in="SourceGraphic" in2="noise" scale="40" />
        </filter>
      </defs>
      <rect width="100%" height="100%" fill="#475569" filter="url(#extremeBlur)"/>
      <circle cx="200" cy="300" r="150" fill="#64748b" filter="url(#extremeBlur)"/>
      <circle cx="400" cy="600" r="180" fill="#334155" filter="url(#extremeBlur)"/>
      <rect x="100" y="200" width="400" height="500" fill="#94a3b8" opacity="0.3" filter="url(#extremeBlur)"/>
    </svg>
    `,
  },
];

async function generateAllFixtures() {
  console.log('Generating 7 genuine synthetic PNG screenshot fixtures with sharp...');
  const outMap: Record<string, { id: string; name: string; mimeType: string; dataUrl: string; simulatedVisualDescription: string }> = {};

  for (const fix of FIXTURES) {
    const pngBuffer = await sharp(Buffer.from(fix.svg))
      .png({ compressionLevel: 9 })
      .toBuffer();
    
    console.log(`✓ ${fix.key}: ${pngBuffer.length} bytes`);
    const dataUrl = `data:${fix.mimeType};base64,${pngBuffer.toString('base64')}`;
    outMap[fix.key] = {
      id: fix.id,
      name: fix.name,
      mimeType: fix.mimeType,
      dataUrl,
      simulatedVisualDescription: fix.description,
    };
  }

  // Write TypeScript file
  const tsContent = `/**
 * HARIS (حارس) — Evaluation Screenshot Fixtures (v1.1.0)
 *
 * Real synthetic PNG fixtures containing authentic visual content and typography
 * for evaluating visual extraction, fallback behavior, and multimodal intelligence.
 * Generated deterministically with sharp; zero 1x1 placeholders.
 */

export interface ScreenshotFixture {
  id: string;
  name: string;
  mimeType: string;
  dataUrl: string;
  simulatedVisualDescription: string;
}

export const SCREENSHOT_FIXTURES: Record<string, ScreenshotFixture> = ${JSON.stringify(outMap, null, 2)};
`;

  const targetPath = path.join(process.cwd(), 'evaluation', 'fixtures', 'screenshots.ts');
  fs.writeFileSync(targetPath, tsContent, 'utf8');
  console.log(`\nSuccessfully wrote real fixtures to: ${targetPath}`);
}

generateAllFixtures().catch(console.error);
