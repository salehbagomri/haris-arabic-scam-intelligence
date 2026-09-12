/**
 * HARIS (حارس) — Deterministic Arabic Text Normalizer
 *
 * Provides deterministic text cleaning, letter normalization, diacritics removal,
 * repeated character deduplication, obfuscation detection, Arabizi conversion,
 * and URL extraction.
 *
 * CRITICAL PRINCIPLE:
 * Preserves the original text intact so that evidence items can accurately quote
 * the original verbatim content.
 */

import { parse as parseDomain } from 'tldts';

export interface NormalizedTextResult {
  /** The untouched original input string */
  originalText: string;

  /** Standardized, normalized text for deterministic rule matching */
  normalizedText: string;

  /** Normalized word tokens */
  tokens: string[];

  /** All URLs extracted from the text */
  extractedUrls: string[];

  /** Signals whether suspicious spacing or obfuscation was detected */
  hasObfuscation: boolean;

  /** Signals whether Arabizi numerals were detected in words */
  hasArabizi: boolean;

  /** Signals whether excessive repetition was pruned */
  hasExcessiveRepetition: boolean;
}

/**
 * Remove Arabic Tashkeel (diacritics) and Tatweel (Kashida)
 */
export function stripDiacriticsAndTatweel(text: string): string {
  return text
    // Remove diacritics (Fat-ha, Damma, Kasra, Shadda, Sukun, Tanween)
    .replace(/[\u064B-\u065F\u0670]/g, '')
    // Remove Tatweel / Kashida
    .replace(/\u0640/g, '');
}

/**
 * Normalize variations of Arabic letters (Alifs, Taa Marbuta, Yaa, Hamzas)
 */
export function normalizeArabicLetters(text: string): string {
  return text
    // Normalize Alef variations (أ, إ, آ, ٱ -> ا)
    .replace(/[أإآٱ]/g, 'ا')
    // Normalize Taa Marbuta to Haa (ة -> ه) for consistent root matching
    .replace(/ة/g, 'ه')
    // Normalize Alef Maqsura to Yaa (ى -> ي)
    .replace(/ى/g, 'ي')
    // Normalize Hamza on Waw / Yaa (ؤ -> و, ئ -> ي)
    .replace(/ؤ/g, 'و')
    .replace(/ئ/g, 'ي');
}

/**
 * Remove excessive character repetitions (e.g. "مبروووووك" -> "مبروك", "ساررررع" -> "سارع")
 */
export function deduplicateRepeatedChars(text: string): { cleaned: string; wasPruned: boolean } {
  // Replace 3 or more identical consecutive characters with a single character
  const regex = /(.)\1{2,}/gu;
  const wasPruned = regex.test(text);
  const cleaned = text.replace(regex, '$1');
  return { cleaned, wasPruned };
}

/**
 * Detect and resolve intentional obfuscation (e.g., spaces or dots between Arabic letters: "ح س ا ب ك" or "ح.س.ا.ب.ك")
 */
export function resolveObfuscation(text: string): { cleaned: string; detected: boolean } {
  // Detect single Arabic letters separated by spaces or dots/dashes (at least 3 letters in a standalone sequence)
  const singleLetterSpacedRegex = /(?<=\s|^)(?:[\u0600-\u06FF][ ._\-]){2,}[\u0600-\u06FF](?=\s|$|[.,!؟])/gu;
  const detected = singleLetterSpacedRegex.test(text);

  let cleaned = text;
  if (detected) {
    cleaned = cleaned.replace(singleLetterSpacedRegex, (match) => {
      return match.replace(/[ ._\-]/g, '');
    });
  }

  return { cleaned, detected };
}

/**
 * Detect and normalize common Arabizi patterns (e.g., 7sabak -> حسابك, 3aziz -> عزيز)
 */
export function normalizeArabizi(text: string): { cleaned: string; detected: boolean } {
  let detected = false;

  // Specific high-frequency Arabizi tokens common in scams
  const arabiziMap: Record<string, string> = {
    '7sabak': 'حسابك',
    '7sabek': 'حسابك',
    '7sab': 'حساب',
    '3aziz': 'عزيز',
    '3azizi': 'عزيزي',
    '5edmah': 'خدمة',
    '5edma': 'خدمة',
    'mabrook': 'مبروك',
    'mbrook': 'مبروك',
    'fawran': 'فورا',
  };

  let cleaned = text;

  // Check word-by-word
  const words = cleaned.split(/\s+/);
  const transformedWords = words.map((w) => {
    const lower = w.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (arabiziMap[lower]) {
      detected = true;
      return arabiziMap[lower];
    }
    // Check if word contains typical Arabizi letter-number mix (e.g. 7سابك or 3ميل)
    if (/[a-zA-Z0-9]+[\u0600-\u06FF]+|[\u0600-\u06FF]+[a-zA-Z0-9]+/.test(w)) {
      detected = true;
      // Replace leading 7 with ح, 3 with ع if prepended to Arabic
      return w.replace(/^7(?=[\u0600-\u06FF])/, 'ح').replace(/^3(?=[\u0600-\u06FF])/, 'ع');
    }
    return w;
  });

  cleaned = transformedWords.join(' ');
  return { cleaned, detected };
}

/**
 * Extract all URLs and bare domains from text with strict lexical validation
 */
export function extractUrlsFromText(text: string): string[] {
  if (!text) return [];

  // Match full URLs with protocols or www, and candidate bare domains
  const candidateRegex = /(?:https?:\/\/|www\.)[^\s/$.?#].[^\s]*|\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+(?:\/[^\s]*)?/gi;
  const rawMatches = text.match(candidateRegex) || [];

  const validUrls: string[] = [];

  for (const item of rawMatches) {
    // Clean trailing punctuation attached from sentence ending
    const cleaned = item.replace(/[),.;!؟]+$/, '').trim();
    if (cleaned.length < 4) continue;

    // If explicit scheme or www, accept
    if (/^(?:https?:\/\/|www\.)/i.test(cleaned)) {
      validUrls.push(cleaned);
      continue;
    }

    // For bare domains, check against ICANN root TLD database via tldts
    // Exclude simple decimal numbers like 3.14 or versions like 1.2
    if (/^\d+\.\d+$/.test(cleaned)) continue;

    const parsed = parseDomain(cleaned);
    const hostOnly = cleaned.split('/')[0].toLowerCase();

    // Check if valid ICANN domain or IP address, and not a document/image file extension
    const isExcludedFileExtension = /\.(?:png|jpg|jpeg|gif|webp|svg|pdf|docx?|xlsx?|txt|zip|tar|gz|exe|apk)$/i.test(hostOnly);

    if ((parsed.isIcann || parsed.isIp) && parsed.domain && !isExcludedFileExtension) {
      validUrls.push(cleaned);
    }
  }

  return Array.from(new Set(validUrls));
}

/**
 * Main Deterministic Normalization Pipeline
 */
export function normalizeArabicText(input: string): NormalizedTextResult {
  const originalText = input || '';

  // 1. Extract URLs first before modifying the string
  const extractedUrls = extractUrlsFromText(originalText);

  // 2. Remove zero-width characters and invisible control formatting
  let processed = originalText
    .replace(/[\u200B-\u200D\uFEFF\u00A0]/g, ' ')
    .replace(/\r\n/g, '\n');

  // 3. Strip Arabic diacritics and tatweel
  processed = stripDiacriticsAndTatweel(processed);

  // 4. Resolve letter-spacing and obfuscation
  const { cleaned: deobfuscated, detected: hasObfuscation } = resolveObfuscation(processed);
  processed = deobfuscated;

  // 5. Deduplicate repeated letters
  const { cleaned: deduped, wasPruned: hasExcessiveRepetition } = deduplicateRepeatedChars(processed);
  processed = deduped;

  // 6. Normalize Arabizi tokens
  const { cleaned: arabiziNormalized, detected: hasArabizi } = normalizeArabizi(processed);
  processed = arabiziNormalized;

  // 7. Normalize Arabic letters
  processed = normalizeArabicLetters(processed);

  // 8. Collapse whitespace
  const normalizedText = processed.replace(/\s+/g, ' ').trim();

  // 9. Generate word tokens (words of length >= 2)
  const tokens = normalizedText
    .toLowerCase()
    .split(/[\s,.;:!؟"'()\[\]{}]+/)
    .filter((t) => t.length > 0);

  return {
    originalText,
    normalizedText,
    tokens,
    extractedUrls,
    hasObfuscation,
    hasArabizi,
    hasExcessiveRepetition,
  };
}
