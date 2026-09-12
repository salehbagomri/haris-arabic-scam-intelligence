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
 * Safely convert a browser/runtime File to a Data URL (data:<mime>;base64,...)
 * Supports standard File.arrayBuffer() across modern browsers and Node runtimes.
 */
export async function fileToDataUrl(file: File): Promise<string> {
  try {
    if (typeof file.arrayBuffer === 'function') {
      const arrayBuffer = await file.arrayBuffer();
      const base64 = Buffer.from(arrayBuffer).toString('base64');
      return `data:${file.type};base64,${base64}`;
    }

    if (typeof FileReader !== 'undefined') {
      return await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          if (typeof reader.result === 'string') {
            resolve(reader.result);
          } else {
            reject(new AnalysisError('تعذر قراءة بيانات ملف الصورة بصيغة صالحة.'));
          }
        };
        reader.onerror = () => {
          reject(new AnalysisError('حدث خطأ أثناء قراءة ملف لقطة الشاشة في المتصفح.'));
        };
        reader.readAsDataURL(file);
      });
    }

    throw new Error('Environment does not support file reading.');
  } catch (err: unknown) {
    if (err instanceof AnalysisError) throw err;
    throw new AnalysisError('تعذر قراءة بيانات ملف الصورة بصيغة صالحة.');
  }
}

/**
 * Map raw server AnalyzeResponse to the UI-compatible AnalysisResult
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
      detail:
        d.explanations.length > 0
          ? d.explanations[0]
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
    throw new AnalysisError(
      'تعذر الاتصال بخادم الفحص. يرجى التحقق من اتصال الإنترنت لديك والمحاولة مجدداً.'
    );
  }

  // 3. Handle non-200 HTTP statuses
  if (!res.ok) {
    let errorMessage = 'حدث خطأ أثناء معالجة الطلب.';
    try {
      const errorJson = (await res.json()) as { error?: string };
      if (errorJson && typeof errorJson.error === 'string') {
        errorMessage = errorJson.error;
      }
    } catch {
      // fallback to status-based message
    }

    if (res.status === 400) {
      throw new AnalysisError(
        `خطأ في التحقق من صحة المدخلات: ${errorMessage}`,
        400
      );
    }

    if (res.status === 413) {
      throw new AnalysisError(
        'حجم الصورة المرفوعة يتجاوز الحد الأقصى المسموح به (10 ميجابايت).',
        413
      );
    }

    if (res.status === 500) {
      throw new AnalysisError(
        'حدث خطأ غير متوقع في خادم التحليل. يرجى المحاولة مرة أخرى لاحقاً.',
        500
      );
    }

    throw new AnalysisError(errorMessage, res.status);
  }

  // 4. Parse and validate 200 response
  let rawJson: unknown;
  try {
    rawJson = await res.json();
  } catch {
    throw new AnalysisError('استجابة خادم الفحص غير صالحة أو تعذر قراءتها.');
  }

  const parseResult = analyzeResponseSchema.safeParse(rawJson);
  if (!parseResult.success) {
    throw new AnalysisError('بنية نتائج التحليل المستلمة من الخادم غير مطابقة للمواصفات.');
  }

  // 5. Map to presentation model
  return mapApiResponseToResult(parseResult.data, mode, inputPreview);
}
