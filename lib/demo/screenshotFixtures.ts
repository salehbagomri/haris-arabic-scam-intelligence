/**
 * HARIS (حارس) — Demo Screenshot Fixture Helpers
 *
 * Provides judge-facing convenience loaders for existing synthetic screenshot
 * evaluation fixtures (SCAM_ARABIC_TEXT and LEGIT_SECURITY_ADVISORY).
 * Strictly converts base64 Data URLs into real browser File objects
 * so they run through the real /api/analyze multimodal pipeline.
 */

import { SCREENSHOT_FIXTURES } from '../../evaluation/fixtures/screenshots';

/**
 * Converts a base64 Data URL to a standard browser File object.
 * Pure Web APIs (atob, Uint8Array, File).
 */
export function dataUrlToFile(dataUrl: string, filename: string): File {
  const parts = dataUrl.split(',');
  const mimeMatch = parts[0].match(/:(.*?);/);
  const mime = mimeMatch ? mimeMatch[1] : 'image/png';
  const bstr = atob(parts[1]);
  let n = bstr.length;
  const u8arr = new Uint8Array(n);
  while (n--) {
    u8arr[n] = bstr.charCodeAt(n);
  }
  return new File([u8arr], filename, { type: mime });
}

export function getDemoScamScreenshotFile(): File {
  return dataUrlToFile(
    SCREENSHOT_FIXTURES.SCAM_ARABIC_TEXT.dataUrl,
    'تنبيه_بنكي_احتيالي_تجريبي.png'
  );
}

export function getDemoLegitScreenshotFile(): File {
  return dataUrlToFile(
    SCREENSHOT_FIXTURES.LEGIT_SECURITY_ADVISORY.dataUrl,
    'تحذير_أمني_مشروع_للمقارنة.png'
  );
}
