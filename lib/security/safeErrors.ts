/**
 * HARIS (حارس) — User-Safe Error Sanitization & Shielding (SEC-FIND-02)
 *
 * Enforces strict error boundary isolation:
 * Internal infrastructure details, Gemini/provider error details, API key configuration,
 * filesystem paths, network endpoints, and raw exception messages NEVER leak to the
 * client via uncertainties, interpretation, or API responses.
 */

export const USER_SAFE_ERROR_MESSAGES = {
  /** Safe Arabic message when screenshot extraction fails (Screenshot-only) */
  INTERPRETATION_EXTRACTION_FAILED:
    'تعذر استخراج أو قراءة محتوى لقطة الشاشة المرفقة. لم يتم التحقق من سلامة المحتوى ولا يعتبر ذلك مؤشراً على أمان الرسالة.',

  /** General extraction failure uncertainty */
  EXTRACTION_FAILED_GENERAL:
    'تعذر استخراج النصوص من لقطة الشاشة آلياً أو حدث خطأ في معالجة الصورة.',

  /** Timeout extraction uncertainty */
  EXTRACTION_TIMEOUT:
    'انتهت المهلة الزمنية المحددة للتحليل البصري (timeout).',

  /** Empty / 0-byte file uncertainty */
  EXTRACTION_EMPTY_FILE:
    'ملف الصورة فارغ أو غير صالح للاستخراج الآلي (0 bytes).',

  /** Unsupported MIME type uncertainty */
  EXTRACTION_UNSUPPORTED_TYPE:
    'صيغة الصورة المرفوعة غير مدعومة للاستخراج الآلي.',

  /** Partial fallback warning when text/URL exists alongside a failing screenshot */
  PARTIAL_EXTRACTION_WARNING:
    'فشل استخراج لقطة الشاشة، واعتمد التحليل على النص/الرابط المدخل فقط.',

  /** Safe Arabic notice when semantic AI is not applied */
  AI_SEMANTIC_UNAVAILABLE:
    'لم يتم تطبيق التحليل الدلالي بالذكاء الاصطناعي في هذا الفحص (يعتمد التقييم على القواعد الحتمية المحلية فقط).',

  /** Generic safe uncertainty disclaimer for unreadable images */
  UNREADABLE_IMAGE_DISCLAIMER:
    'نتيجة الفحص غير محددة لتعذر قراءة الصورة ولا تعني بأي حال من الأحوال أن الرسالة آمنة.',
};

/**
 * Redact sensitive tokens, API keys, and filesystem paths from internal diagnostic strings
 */
export function sanitizeInternalErrorMessage(message: string): string {
  if (!message || typeof message !== 'string') return '';
  let sanitized = message;

  // Redact potential API keys or tokens (e.g. Gemini AIza..., generic hex/base64 tokens)
  sanitized = sanitized.replace(/AIza[0-9A-Za-z-_]{35}/g, '[REDACTED_API_KEY]');
  sanitized = sanitized.replace(/key=[^&\s]+/gi, 'key=[REDACTED]');
  sanitized = sanitized.replace(/bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED]');

  // Redact Windows or Unix absolute file paths
  sanitized = sanitized.replace(/[a-zA-Z]:\\[^\s:;,]+/g, '[REDACTED_PATH]');
  sanitized = sanitized.replace(/\/(?:home|var|usr|etc|tmp|my_projects)\/[a-zA-Z0-9_./-]+/gi, '[REDACTED_PATH]');

  return sanitized;
}

/**
 * Translate any technical or internal fallback reason into a standardized,
 * user-safe Arabic uncertainty statement that never leaks infrastructure or provider details.
 */
export function sanitizeToUserSafeUncertainty(technicalReason?: string): string {
  if (!technicalReason || typeof technicalReason !== 'string') {
    return USER_SAFE_ERROR_MESSAGES.EXTRACTION_FAILED_GENERAL;
  }

  const lower = technicalReason.toLowerCase();

  // 1. Timeout cases
  if (lower.includes('timeout') || lower.includes('timed out') || lower.includes('abort')) {
    return USER_SAFE_ERROR_MESSAGES.EXTRACTION_TIMEOUT;
  }

  // 2. Empty / invalid image payloads (input validation, safe to inform user)
  if (lower.includes('0 bytes') || lower.includes('empty')) {
    return USER_SAFE_ERROR_MESSAGES.EXTRACTION_EMPTY_FILE;
  }

  if (lower.includes('unsupported image') || lower.includes('mime type')) {
    return USER_SAFE_ERROR_MESSAGES.EXTRACTION_UNSUPPORTED_TYPE;
  }

  // 3. All other internal errors:
  // - Missing GEMINI_API_KEY
  // - GoogleGenAIError / Provider 403 / 500
  // - Network errors (ECONNREFUSED, ENOTFOUND)
  // - JSON parse / Zod schema validation errors
  // - Internal stack traces
  // -> Return generic user-safe Arabic message
  return USER_SAFE_ERROR_MESSAGES.EXTRACTION_FAILED_GENERAL;
}
