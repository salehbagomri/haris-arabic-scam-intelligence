/**
 * HARIS (حارس) — Semantic Intelligence Analyzer
 *
 * Executes Gemini semantic reasoning queries with timeout protection,
 * failure recovery, and zero-crash fallback guarantees.
 */

import { GoogleGenAI } from '@google/genai';
import { getGeminiClient, getConfiguredModel, getGeminiTimeoutMs } from './client';
import { GeminiInputContext, GeminiSemanticAnalysis } from './schema';
import { HARIS_SYSTEM_PROMPT, buildUserPrompt } from './prompts';
import { parseAndValidateSemanticOutput } from './parser';

export interface SemanticAnalysisExecutionResult {
  success: boolean;
  data?: GeminiSemanticAnalysis;
  modelUsed?: string;
  fallbackReason?: string;
}

export interface SemanticAnalyzerOptions {
  client?: GoogleGenAI | null;
  model?: string;
  timeoutMs?: number;
}

/**
 * Execute semantic reasoning using Gemini API with strict error boundaries
 */
export async function analyzeSemantics(
  context: GeminiInputContext,
  options: SemanticAnalyzerOptions = {}
): Promise<SemanticAnalysisExecutionResult> {
  const client = options.client !== undefined ? options.client : getGeminiClient();
  const model = options.model || getConfiguredModel();
  const timeoutMs = options.timeoutMs || getGeminiTimeoutMs();

  // 1. Guard against unconfigured or missing API key
  if (!client) {
    return {
      success: false,
      fallbackReason: 'Gemini API is not configured on the server (GEMINI_API_KEY missing or empty).',
    };
  }

  // 2. Prepare user prompt payload
  const promptText = buildUserPrompt(context);

  try {
    // 3. Execute with Timeout Guard
    const abortController = new AbortController();
    const timeoutId = setTimeout(() => abortController.abort(), timeoutMs);

    let response;
    try {
      response = await client.models.generateContent({
        model,
        contents: [
          {
            role: 'user',
            parts: [{ text: promptText }],
          },
        ],
        config: {
          systemInstruction: HARIS_SYSTEM_PROMPT,
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
        fallbackReason: 'Gemini model returned an empty response.',
      };
    }

    // 4. Parse, validate with Zod, and enforce anti-hallucination guards
    const parseResult = parseAndValidateSemanticOutput(
      rawResponseText,
      context.originalText,
      context.normalizedText
    );

    if (!parseResult.success || !parseResult.data) {
      return {
        success: false,
        fallbackReason: `Semantic validation failed: ${parseResult.error || 'Invalid model output'}`,
      };
    }

    return {
      success: true,
      data: parseResult.data,
      modelUsed: model,
    };
  } catch (err: unknown) {
    // 5. Catch all errors without throwing; never log sensitive message payloads or credentials
    const errorMessage = err instanceof Error ? err.message : String(err);
    const isTimeout = errorMessage.includes('abort') || errorMessage.includes('timeout');

    return {
      success: false,
      fallbackReason: isTimeout
        ? `Gemini request timed out after ${timeoutMs}ms.`
        : `Gemini API execution error: ${errorMessage}`,
    };
  }
}
