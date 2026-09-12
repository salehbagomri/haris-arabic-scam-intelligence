/**
 * HARIS (حارس) — Unified Analysis API Route Handler
 *
 * Endpoint: POST /api/analyze
 * Provides a single canonical server-side entry point for text, URL,
 * and screenshot scam intelligence analysis.
 */

import { analyzeRequestSchema, AnalyzeResponse } from '../../../lib/api/schema';
import { analyzeUnified, UnifiedPipelineOptions, ScreenshotInput } from '../../../lib/vision';
import { VISION_CONFIG } from '../../../lib/config/vision';

export interface ApiResponsePayload {
  status: number;
  data: AnalyzeResponse | { error: string };
}

/**
 * Core analysis handler shared by HTTP route and programmatic invocation
 */
export async function handleAnalyze(
  body: unknown,
  options?: UnifiedPipelineOptions
): Promise<ApiResponsePayload> {
  // 1. Validate request payload with Zod schema
  const validation = analyzeRequestSchema.safeParse(body);
  if (!validation.success) {
    const errorMsg = validation.error.issues.map((i) => i.message).join('; ');
    return {
      status: 400,
      data: { error: errorMsg },
    };
  }

  const { text, url, screenshot } = validation.data;

  // 2. Process and validate screenshot payload if present
  let screenshotInput: ScreenshotInput | undefined;
  if (screenshot) {
    const cleanBase64 = screenshot.data
      .replace(/^data:image\/[a-z0-9+.-]+;base64,/i, '')
      .trim();

    let buffer: Buffer;
    try {
      buffer = Buffer.from(cleanBase64, 'base64');
    } catch {
      return {
        status: 400,
        data: { error: 'Invalid base64 encoding in screenshot data.' },
      };
    }

    // Check for empty image data
    if (buffer.length === 0) {
      return {
        status: 400,
        data: { error: 'Screenshot data is empty (0 bytes).' },
      };
    }

    // Check 10 MB payload limit -> HTTP 413 Payload Too Large
    if (buffer.length > VISION_CONFIG.maxImageSizeBytes) {
      return {
        status: 413,
        data: {
          error: `Screenshot payload (${(buffer.length / 1024 / 1024).toFixed(2)} MB) exceeds maximum permitted size of ${VISION_CONFIG.maxImageSizeBytes / 1024 / 1024} MB.`,
        },
      };
    }

    screenshotInput = {
      buffer,
      mimeType: screenshot.mimeType,
    };
  }

  try {
    // 3. Execute unified multimodal analysis pipeline
    const fused = await analyzeUnified(
      {
        text,
        url,
        screenshot: screenshotInput,
      },
      options
    );

    // 4. Format typed public response contract
    const responseData: AnalyzeResponse = {
      riskLevel: fused.riskLevel,
      riskScore: fused.riskScore,
      scamType: fused.scamType,
      scamTypeNameAr: fused.scamTypeNameAr,
      interpretation: fused.interpretation,
      scamDna: fused.scamDna.map((d) => ({
        featureId: d.featureId,
        nameAr: d.nameAr,
        nameEn: d.nameEn,
        detected: d.detected,
        severity: d.severity,
        provenance: d.provenance,
        evidence: d.evidence,
        explanations: d.explanations,
      })),
      evidence: fused.evidence.map((e) => ({
        id: e.id,
        title: e.title,
        description: e.description,
        severity: e.severity,
        source: e.source,
        provenance: e.provenance,
      })),
      actionableAdvice: fused.actionableAdvice,
      uncertainties: fused.uncertainties,
      aiConfidence: fused.aiConfidence,
      extractionConfidence: fused.visualExtraction?.extractionConfidence ?? null,
      isExtractionFailure: fused.isExtractionFailure ?? false,
      analyzedAt: new Date().toISOString(),
    };

    return {
      status: 200,
      data: responseData,
    };
  } catch {
    // Never leak stack traces, internal paths, or API keys in response or logs
    return {
      status: 500,
      data: { error: 'An unexpected internal error occurred during analysis.' },
    };
  }
}

/**
 * Route Handler for POST /api/analyze
 */
export async function POST(request: Request): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json(
      { error: 'Invalid JSON payload in request body.' },
      { status: 400 }
    );
  }

  const result = await handleAnalyze(body);
  return Response.json(result.data, { status: result.status });
}
