/**
 * HARIS (حارس) — Server-side Google Gemini Client
 *
 * CRITICAL SECURITY PRINCIPLES:
 * 1. SERVER-SIDE ONLY: NEVER import or execute this module in client components.
 * 2. API KEY PRIVACY: Never expose GEMINI_API_KEY to browser bundles or logs.
 * 3. CONFIGURABLE: Model name and timeout are managed via environment variables.
 */

import { GoogleGenAI } from '@google/genai';

let cachedClient: GoogleGenAI | null = null;

/**
 * Check if the Gemini API key is configured on the server
 */
export function isGeminiConfigured(): boolean {
  const key = process.env.GEMINI_API_KEY;
  return typeof key === 'string' && key.trim().length > 0 && key !== 'your_gemini_api_key_here';
}

/**
 * Retrieve configured Gemini model name with stable fallback
 */
export function getConfiguredModel(): string {
  return process.env.GEMINI_MODEL?.trim() || 'gemini-2.5-flash';
}

/**
 * Retrieve execution timeout for Gemini API calls in milliseconds
 */
export function getGeminiTimeoutMs(): number {
  const parsed = Number(process.env.GEMINI_TIMEOUT_MS);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 12000;
}

/**
 * Obtain singleton GoogleGenAI instance or null if unconfigured
 */
export function getGeminiClient(): GoogleGenAI | null {
  if (!isGeminiConfigured()) {
    return null;
  }

  if (!cachedClient) {
    const apiKey = process.env.GEMINI_API_KEY?.trim();
    cachedClient = new GoogleGenAI({ apiKey });
  }

  return cachedClient;
}

/**
 * Reset client cache (primarily for unit testing with mocked credentials)
 */
export function resetGeminiClientCache(): void {
  cachedClient = null;
}
