import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  normalizeArabicText,
  stripDiacriticsAndTatweel,
  normalizeArabicLetters,
  deduplicateRepeatedChars,
  resolveObfuscation,
  normalizeArabizi,
  extractUrlsFromText,
} from '../lib/analysis/normalizer';

describe('Arabic Normalizer Tests', () => {
  it('should strip tashkeel diacritics and tatweel properly', () => {
    const input = 'مُبَــــارَكٌ لَكَ يَا عَزِيْزِيْ';
    const output = stripDiacriticsAndTatweel(input);
    assert.strictEqual(output, 'مبارك لك يا عزيزي');
  });

  it('should normalize Arabic letters variations (Alifs, Taa Marbuta, Yaa)', () => {
    const input = 'أحمد إلى إبراهيم في مكة المكرمة وعلى هدى';
    const output = normalizeArabicLetters(input);
    assert.strictEqual(output, 'احمد الي ابراهيم في مكه المكرمه وعلي هدي');
  });

  it('should prune excessive character repetition', () => {
    const input = 'مبروووووووك فززززت معناااااا';
    const { cleaned, wasPruned } = deduplicateRepeatedChars(input);
    assert.strictEqual(wasPruned, true);
    assert.strictEqual(cleaned, 'مبروك فزت معنا');
  });

  it('should detect and resolve obfuscated spaced text', () => {
    const input = 'يرجى تحديث ح س ا ب ك فوراً';
    const { cleaned, detected } = resolveObfuscation(input);
    assert.strictEqual(detected, true);
    assert.strictEqual(cleaned, 'يرجى تحديث حسابك فوراً');
  });

  it('should detect Arabizi numerals mixed in words', () => {
    const input = '7sabak تم ايقافه يا 3aziz';
    const { cleaned, detected } = normalizeArabizi(input);
    assert.strictEqual(detected, true);
    assert.ok(cleaned.includes('حسابك'));
    assert.ok(cleaned.includes('عزيز'));
  });

  it('should extract embedded URLs accurately and clean punctuation', () => {
    const input = 'اضغط على الرابط: https://alrajhi-secure.xyz/verify! للمزيد راجع www.spl-tracking.top.';
    const urls = extractUrlsFromText(input);
    assert.strictEqual(urls.length, 2);
    assert.strictEqual(urls[0], 'https://alrajhi-secure.xyz/verify');
    assert.strictEqual(urls[1], 'www.spl-tracking.top');
  });

  it('should process full pipeline and keep originalText intact', () => {
    const raw = 'عزيزي، ح س ا ب ك تم إيقافه مؤقتاً! اضغط https://bank-login.xyz للتفعيل.';
    const res = normalizeArabicText(raw);
    assert.strictEqual(res.originalText, raw);
    assert.strictEqual(res.hasObfuscation, true);
    assert.strictEqual(res.extractedUrls.length, 1);
    assert.ok(res.normalizedText.includes('حسابك'));
    assert.ok(res.normalizedText.includes('ايقافه'));
  });
});
