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

let analyzePipelineFn = analyzeUnified;

/**
 * Override the underlying analysis pipeline for unit/behavioral testing.
 */
export function setAnalyzePipelineForTesting(fn: typeof analyzeUnified | null): void {
  analyzePipelineFn = fn || analyzeUnified;
}

/**
 * Core analysis handler shared by HTTP route and programmatic invocation
 */
export async function handleAnalyze(
  body: unknown,
  options?: UnifiedPipelineOptions
): Promise<ApiResponsePayload> {
  // 1. Validate request payload with strict Zod schema
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
    const rawData = screenshot.data.trim();
    let base64Payload = rawData;

    // Support Data URL format: data:<mimeType>;base64,<payload>
    if (rawData.startsWith('data:')) {
      const commaIdx = rawData.indexOf(',');
      if (commaIdx === -1) {
        return {
          status: 400,
          data: { error: 'Invalid Data URL format for screenshot: missing comma separator.' },
        };
      }

      const header = rawData.slice(0, commaIdx);
      base64Payload = rawData.slice(commaIdx + 1).trim();

      // Parse MIME type from header: e.g. data:image/png;base64
      const headerMatch = header.match(
        /^data:([a-zA-Z0-9+.-]+\/[a-zA-Z0-9+.-]+)(?:;[a-zA-Z0-9+.-]+=[^;]+)*;base64$/i
      );
      if (!headerMatch) {
        return {
          status: 400,
          data: { error: 'Invalid Data URL header format. Expected "data:<mimeType>;base64,".' },
        };
      }

      const prefixMime = headerMatch[1].trim().toLowerCase();
      const expectedMime = screenshot.mimeType.trim().toLowerCase();
      if (prefixMime !== expectedMime) {
        return {
          status: 400,
          data: {
            error: `Data URL MIME type (${prefixMime}) does not match specified screenshot.mimeType (${screenshot.mimeType}).`,
          },
        };
      }
    }

    // Fast-path size check using decoded length formula before allocating large buffer or running regex
    const paddingCount = base64Payload.endsWith('==') ? 2 : base64Payload.endsWith('=') ? 1 : 0;
    const estimatedByteLength = (base64Payload.length / 4) * 3 - paddingCount;

    if (estimatedByteLength === 0) {
      return {
        status: 400,
        data: { error: 'Screenshot data is empty (0 bytes).' },
      };
    }

    if (estimatedByteLength > VISION_CONFIG.maxImageSizeBytes) {
      return {
        status: 413,
        data: {
          error: `Screenshot payload (${(estimatedByteLength / 1024 / 1024).toFixed(2)} MB) exceeds maximum permitted size of ${VISION_CONFIG.maxImageSizeBytes / 1024 / 1024} MB.`,
        },
      };
    }

    // Canonical Base64 validation before decoding
    // Standard Base64 requires length to be a positive multiple of 4, composed solely of
    // [A-Za-z0-9+/] with at most two trailing '=' padding characters.
    // Uses linear non-backtracking regex to prevent call stack overflow on large inputs.
    const LINEAR_BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;

    if (
      base64Payload.length === 0 ||
      base64Payload.length % 4 !== 0 ||
      !LINEAR_BASE64_REGEX.test(base64Payload)
    ) {
      return {
        status: 400,
        data: { error: 'Invalid or malformed Base64 encoding in screenshot data.' },
      };
    }

    // Decode buffer
    const buffer = Buffer.from(base64Payload, 'base64');
    if (buffer.length === 0) {
      return {
        status: 400,
        data: { error: 'Screenshot data is empty (0 bytes).' },
      };
    }

    // Enforce 10 MB limit on decoded buffer
    if (buffer.length > VISION_CONFIG.maxImageSizeBytes) {
      return {
        status: 413,
        data: {
          error: `Screenshot payload (${(buffer.length / 1024 / 1024).toFixed(2)} MB) exceeds maximum permitted size of ${VISION_CONFIG.maxImageSizeBytes / 1024 / 1024} MB.`,
        },
      };
    }

    // Verify canonical encoding (catches non-canonical trailing padding bits)
    if (buffer.toString('base64') !== base64Payload) {
      return {
        status: 400,
        data: { error: 'Non-canonical Base64 encoding in screenshot data.' },
      };
    }

    screenshotInput = {
      buffer,
      mimeType: screenshot.mimeType,
    };
  }

  try {
    // 3. Execute unified multimodal analysis pipeline
    const fused = await analyzePipelineFn(
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
  try {
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
  } catch {
    return Response.json(
      { error: 'An unexpected internal error occurred during analysis.' },
      { status: 500 }
    );
  }
}
