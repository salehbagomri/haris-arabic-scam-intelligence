/**
 * HARIS (حارس) — Screenshot Multimodal Vision Analyzer
 *
 * Server-side engine for executing Gemini Vision extraction requests.
 * Enforces resource boundaries, timeout guards, and zero-crash fallback guarantees.
 */

import { GoogleGenAI } from '@google/genai';
import { getGeminiClient, getConfiguredModel, getGeminiTimeoutMs } from '../ai/client';
import { ScreenshotInput, ScreenshotExtractionData } from './schema';
import { HARIS_VISION_SYSTEM_PROMPT, HARIS_VISION_USER_PROMPT } from './prompts';
import { parseAndValidateVisionOutput } from './parser';
import { validateImageConstraints, VISION_CONFIG } from '../config/vision';

export interface VisionExecutionResult {
  success: boolean;
  data?: ScreenshotExtractionData;
  modelUsed?: string;
  fallbackReason?: string;
}

export interface VisionAnalyzerOptions {
  client?: GoogleGenAI | null;
  model?: string;
  timeoutMs?: number;
}

/**
 * Execute multimodal vision analysis on screenshot input
 */
export async function extractScreenshotContent(
  input: ScreenshotInput,
  options: VisionAnalyzerOptions = {}
): Promise<VisionExecutionResult> {
  // 1. Strict Server-Side Execution Guard
  if (typeof window !== 'undefined') {
    return {
      success: false,
      fallbackReason: 'Vision analysis cannot be executed client-side.',
    };
  }

  // 2. Resource & Image Constraint Validation
  const validation = validateImageConstraints(input);
  if (!validation.valid) {
    return {
      success: false,
      fallbackReason: validation.error || 'Invalid screenshot payload.',
    };
  }

  // 3. Resolve base64 data safely without persisting bytes to disk
  let base64Data: string;
  if (input.buffer) {
    base64Data = input.buffer.toString('base64');
  } else if (input.base64) {
    base64Data = input.base64.replace(/^data:image\/[a-z0-9+.-]+;base64,/i, '').trim();
  } else {
    return {
      success: false,
      fallbackReason: 'Missing image payload.',
    };
  }

  const client = options.client !== undefined ? options.client : getGeminiClient();
  const model = options.model || getConfiguredModel();
  const timeoutMs = options.timeoutMs || getGeminiTimeoutMs() || VISION_CONFIG.defaultTimeoutMs;

  // 4. Guard against unconfigured API key
  if (!client) {
    return {
      success: false,
      fallbackReason: 'Gemini API is not configured on the server (GEMINI_API_KEY missing or empty).',
    };
  }

  try {
    // 5. Timeout Guard via AbortController
    const abortController = new AbortController();
    const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);

    let response;
    try {
      response = await client.models.generateContent({
        model,
        contents: [
          {
            role: 'user',
            parts: [
              {
                inlineData: {
                  data: base64Data,
                  mimeType: input.mimeType,
                },
              },
              {
                text: HARIS_VISION_USER_PROMPT,
              },
            ],
          },
        ],
        config: {
          systemInstruction: HARIS_VISION_SYSTEM_PROMPT,
          responseMimeType: 'application/json',
          temperature: 0.1,
          abortSignal: abortController.signal,
        },
      });
    } finally {
      clearTimeout(timeoutId);
    }

    const rawResponseText = response?.text || '';
    if (!rawResponseText || rawResponseText.trim().length === 0) {
      return {
        success: false,
        fallbackReason: 'Gemini Vision returned an empty extraction response.',
      };
    }

    // 6. Parse, validate schema, and ground evidence
    const parseResult = parseAndValidateVisionOutput(rawResponseText);
    if (!parseResult.success || !parseResult.data) {
      return {
        success: false,
        fallbackReason: parseResult.error || 'Failed to parse vision model extraction output.',
      };
    }

    return {
      success: true,
      data: parseResult.data,
      modelUsed: model,
    };
  } catch (err: unknown) {
    // 7. Graceful error recovery: never crash, never log image data or sensitive credentials
    const errorMessage = err instanceof Error ? err.message : String(err);
    const isTimeout = errorMessage.includes('abort') || errorMessage.includes('timeout');

    return {
      success: false,
      fallbackReason: isTimeout
        ? `Vision analysis timed out after ${timeoutMs}ms.`
        : `Vision execution error: ${errorMessage}`,
    };
  }
}
