/**
 * HARIS (حارس) — Frontend Analysis Service
 *
 * Connects user input modes to the canonical POST /api/analyze endpoint,
 * handling serialization, Base64 conversion, strict error normalization,
 * and mapping to UI presentation types.
 */

import { AnalyzeRequest, AnalyzeResponse, analyzeResponseSchema } from '../api/schema';
import { AnalysisResult, InputMode } from '../types/analysis';
import { VISION_CONFIG, isAllowedImageMimeType } from '../config/vision';

export const SAFE_CLIENT_ERROR_MESSAGES = {
  BAD_REQUEST: 'تعذر التحقق من صحة المدخلات المرسلة. يرجى مراجعة النص أو الرابط أو ملف لقطة الشاشة والمحاولة مجدداً.',
  PAYLOAD_TOO_LARGE: 'حجم لقطة الشاشة المرفوعة يتجاوز الحد الأقصى المسموح به (10 ميجابايت).',
  SERVER_ERROR: 'حدث خطأ غير متوقع في خادم التحليل أثناء معالجة المحتوى. يرجى المحاولة مرة أخرى لاحقاً.',
  NETWORK_ERROR: 'تعذر الاتصال بخادم الفحص. يرجى التحقق من اتصال الإنترنت لديك والمحاولة مجدداً.',
  MALFORMED_RESPONSE: 'استجابة خادم الفحص غير صالحة أو غير متوقعة. يرجى إعادة المحاولة لاحقاً.',
  FILE_READ_ERROR: 'تعذر قراءة بيانات ملف الصورة بصيغة صالحة في المتصفح.',
} as const;

export interface ExecuteAnalysisParams {
  mode: InputMode;
  text?: string;
  url?: string;
  screenshotFile?: File | null;
}

export class AnalysisError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
    public readonly isUserSafe: boolean = true
  ) {
    super(message);
    this.name = 'AnalysisError';
  }
}

/**
 * Browser-compatible conversion of ArrayBuffer to Base64 using standard Web primitives
 * (Uint8Array, String.fromCharCode, window.btoa / globalThis.btoa).
 * Does NOT require or use Node's `Buffer` object.
 * Operates in 32KB chunks to prevent maximum call stack size exceeded errors on large files.
 */
export function arrayBufferToBase64Web(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const len = bytes.byteLength;
  const chunkSize = 0x8000; // 32,768 bytes per chunk
  for (let i = 0; i < len; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, len));
    binary += String.fromCharCode.apply(null, chunk as unknown as number[]);
  }
  return btoa(binary);
}

/**
 * Safely convert a browser/runtime File to a Data URL (data:<mime>;base64,...)
 * Uses standard Web APIs (FileReader or File.arrayBuffer() + arrayBufferToBase64Web).
 * Completely free of Node.js Buffer dependencies for 100% browser compatibility.
 */
export async function fileToDataUrl(file: File): Promise<string> {
  // Strategy A: Native browser FileReader (standard in all modern browsers)
  if (typeof FileReader !== 'undefined') {
    return new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        if (typeof reader.result === 'string') {
          resolve(reader.result);
        } else {
          reject(new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.FILE_READ_ERROR));
        }
      };
      reader.onerror = () => {
        reject(new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.FILE_READ_ERROR));
      };
      reader.readAsDataURL(file);
    });
  }

  // Strategy B: Standard Web API File.arrayBuffer() + pure Web Base64 conversion (btoa)
  if (typeof file.arrayBuffer === 'function') {
    try {
      const arrayBuffer = await file.arrayBuffer();
      const base64 = arrayBufferToBase64Web(arrayBuffer);
      const mime = file.type || 'image/png';
      return `data:${mime};base64,${base64}`;
    } catch {
      throw new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.FILE_READ_ERROR);
    }
  }

  throw new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.FILE_READ_ERROR);
}

/**
 * Map raw server AnalyzeResponse to the UI-compatible AnalysisResult.
 * Preserves all intelligence indicators, complete Scam DNA evidence, and explanations.
 */
export function mapApiResponseToResult(
  response: AnalyzeResponse,
  inputMode: InputMode,
  inputPreview: string
): AnalysisResult {
  return {
    isMockData: false,
    inputMode,
    inputPreview,
    riskScore: response.riskScore,
    riskLevel: response.riskLevel,
    scamType: response.scamType,
    scamTypeNameAr: response.scamTypeNameAr,
    summary: response.interpretation,
    scamDna: response.scamDna.map((d) => ({
      id: d.featureId,
      nameAr: d.nameAr,
      nameEn: d.nameEn,
      detected: d.detected,
      severity: d.severity,
      provenance: d.provenance,
      evidence: d.evidence ? [...d.evidence] : [],
      explanations: d.explanations ? [...d.explanations] : [],
      detail:
        d.explanations && d.explanations.length > 0
          ? d.explanations.join(' • ')
          : d.detected
          ? 'تم رصد هذا المؤشر كجزء من نمط التهديد'
          : 'لم يتم رصد هذا المؤشر في المحتوى المفحوص',
    })),
    evidence: response.evidence.map((e) => ({
      id: e.id,
      title: e.title,
      description: e.description,
      severity: e.severity,
      source: e.source,
      provenance: e.provenance,
    })),
    actionableAdvice: response.actionableAdvice,
    uncertainties: response.uncertainties,
    aiConfidence: response.aiConfidence,
    extractionConfidence: response.extractionConfidence,
    isExtractionFailure: response.isExtractionFailure,
    analyzedAt: new Date(response.analyzedAt).toLocaleDateString('ar-SA', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }),
  };
}

/**
 * Send content to POST /api/analyze and return a structured AnalysisResult
 */
export async function executeRealAnalysis(
  params: ExecuteAnalysisParams,
  fetchImpl: typeof fetch = fetch
): Promise<AnalysisResult> {
  const { mode, text, url, screenshotFile } = params;

  let requestBody: AnalyzeRequest;
  let inputPreview = '';

  // 1. Build request contract based on mode with client-side guardrails
  if (mode === 'text') {
    const trimmed = (text || '').trim();
    if (!trimmed) {
      throw new AnalysisError('يرجى كتابة أو لصق نص الرسالة المشبوهة أولاً.');
    }
    if (trimmed.length > 5000) {
      throw new AnalysisError('نص الرسالة طويل جداً (الحد الأقصى 5,000 حرف).');
    }
    requestBody = { text: trimmed };
    inputPreview = trimmed;
  } else if (mode === 'url') {
    const trimmed = (url || '').trim();
    if (!trimmed) {
      throw new AnalysisError('يرجى إدخال الرابط المشبوه للفحص.');
    }
    if (trimmed.length > 2048) {
      throw new AnalysisError('الرابط طويل جداً (الحد الأقصى 2,048 حرفاً).');
    }
    requestBody = { url: trimmed };
    inputPreview = trimmed;
  } else if (mode === 'screenshot') {
    if (!screenshotFile) {
      throw new AnalysisError('يرجى اختيار لقطة شاشة للتحليل.');
    }

    if (!isAllowedImageMimeType(screenshotFile.type)) {
      throw new AnalysisError(
        `صيغة الصورة (${screenshotFile.type || 'غير معروفة'}) غير مدعومة. الصيغ المدعومة: PNG, JPG, WEBP, HEIC, GIF.`
      );
    }

    if (screenshotFile.size > VISION_CONFIG.maxImageSizeBytes) {
      throw new AnalysisError(
        `حجم لقطة الشاشة (${(screenshotFile.size / 1024 / 1024).toFixed(1)} م.ب) يتجاوز الحد الأقصى المسموح به (10 ميجابايت).`,
        413
      );
    }

    const dataUrl = await fileToDataUrl(screenshotFile);
    requestBody = {
      screenshot: {
        mimeType: screenshotFile.type,
        data: dataUrl,
      },
    };
    inputPreview = screenshotFile.name;
  } else {
    throw new AnalysisError('نوع الإدخال المحدد غير مدعوم.');
  }

  // 2. Perform HTTP request to server route
  let res: Response;
  try {
    res = await fetchImpl('/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(requestBody),
    });
  } catch {
    throw new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.NETWORK_ERROR);
  }

  // 3. Handle non-200 HTTP statuses (Strictly Sanitized: NEVER exposes errorJson.error or server details)
  if (!res.ok) {
    if (res.status === 400) {
      throw new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.BAD_REQUEST, 400);
    }

    if (res.status === 413) {
      throw new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.PAYLOAD_TOO_LARGE, 413);
    }

    if (res.status === 500) {
      throw new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.SERVER_ERROR, 500);
    }

    // Generic fallback for any other unexpected HTTP status
    throw new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.SERVER_ERROR, res.status);
  }

  // 4. Parse and validate 200 response
  let rawJson: unknown;
  try {
    rawJson = await res.json();
  } catch {
    throw new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.MALFORMED_RESPONSE);
  }

  const parseResult = analyzeResponseSchema.safeParse(rawJson);
  if (!parseResult.success) {
    throw new AnalysisError(SAFE_CLIENT_ERROR_MESSAGES.MALFORMED_RESPONSE);
  }

  // 5. Map to presentation model
  return mapApiResponseToResult(parseResult.data, mode, inputPreview);
}
