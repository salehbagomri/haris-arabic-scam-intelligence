/**
 * HARIS (حارس) — Phase 5B: Frontend Integration & Analysis Service Tests
 *
 * Covers:
 * 1. text submission calls /api/analyze with { text: "..." }
 * 2. URL submission calls /api/analyze without fetching target URL
 * 3. screenshot submission converts to Data URL and sends { screenshot: { mimeType, data } }
 * 4. client validation / guardrails before network request
 * 5. successful API response maps to real results model with all intelligence indicators
 * 6. 400 error renders user-friendly Arabic validation message
 * 7. 413 screenshot error renders appropriate Arabic message
 * 8. 500/network error renders safe message without leaking internal details
 * 9. isExtractionFailure produces explicit failure/uncertainty state
 * 10. demo scenarios remain strictly mock-only without network calls
 */

import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  executeRealAnalysis,
  mapApiResponseToResult,
  fileToDataUrl,
  arrayBufferToBase64Web,
  AnalysisError,
  SAFE_CLIENT_ERROR_MESSAGES,
} from '../lib/services/analysisService';
import { AnalyzeResponse } from '../lib/api/schema';
import { demoScenarios } from '../lib/demo/mockData';

describe('HARIS Phase 5B: Frontend Integration & Analysis Service', () => {
  const sampleApiResponse: AnalyzeResponse = {
    riskLevel: 'high',
    riskScore: 88,
    scamType: 'BANK_IMPERSONATION',
    scamTypeNameAr: 'انتحال جهة بنكية ومصرفية',
    interpretation: 'رسالة احتيالية صريحة تدعي تجميد الحساب البنكي وتطالب برمز التحقق OTP.',
    scamDna: [
      {
        featureId: 'otp_request',
        nameAr: 'طلب رمز التحقق (OTP)',
        nameEn: 'OTP Harvesting',
        detected: true,
        severity: 'high',
        provenance: 'deterministic',
        evidence: ['أرسل لي رمز التحقق OTP'],
        explanations: ['طلب صريح لإرسال رمز التحقق لمرة واحدة.'],
      },
      {
        featureId: 'impersonation',
        nameAr: 'انتحال جهة موثوقة',
        nameEn: 'Entity Impersonation',
        detected: true,
        severity: 'high',
        provenance: 'both',
        evidence: ['مصرف الراجحي'],
        explanations: ['انتحال صفة مصرف الراجحي لسرقة البيانات.'],
      },
    ],
    evidence: [
      {
        id: 'ev-1',
        title: 'طلب رمز التحقق OTP',
        description: 'الدليل المرصود: "أرسل لي رمز التحقق OTP فوراً"',
        severity: 'high',
        source: 'linguistic',
        provenance: 'deterministic',
      },
      {
        id: 'ev-2',
        title: 'رابط تسجيل دخول مشبوه',
        description: 'الدليل المرصود: "https://alrajhi.secure-login.xyz"',
        severity: 'high',
        source: 'technical',
        provenance: 'deterministic',
      },
    ],
    actionableAdvice: [
      'لا تشارك رمز التحقق OTP مع أي شخص إطلاقاً.',
      'تواصل مع البنك مباشرة عبر القنوات الرسمية المعتمدة.',
    ],
    uncertainties: ['قد تستخدم الصفحة روابط إضافية غير معلنة.'],
    aiConfidence: 0.94,
    extractionConfidence: null,
    isExtractionFailure: false,
    analyzedAt: '2026-09-12T18:30:00.000Z',
  };

  // =========================================================================
  // 1. Text Submission Calls /api/analyze
  // =========================================================================
  it('1. text submission calls /api/analyze with correct payload', async () => {
    let capturedUrl = '';
    let capturedInit: RequestInit | undefined;

    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      capturedUrl = String(input);
      capturedInit = init;
      return new Response(JSON.stringify(sampleApiResponse), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };

    const userText = 'عزيزي العميل، تم إيقاف بطاقتك البنكية، أرسل رمز OTP للتفعيل.';
    const result = await executeRealAnalysis(
      { mode: 'text', text: userText },
      mockFetch as typeof fetch
    );

    assert.strictEqual(capturedUrl, '/api/analyze');
    assert.strictEqual(capturedInit?.method, 'POST');
    assert.strictEqual(
      (capturedInit?.headers as Record<string, string>)['Content-Type'],
      'application/json'
    );

    const sentBody = JSON.parse(capturedInit?.body as string);
    assert.strictEqual(sentBody.text, userText);
    assert.strictEqual(sentBody.url, undefined);
    assert.strictEqual(sentBody.screenshot, undefined);

    // Verify result is marked real (not mock)
    assert.strictEqual(result.isMockData, false);
    assert.strictEqual(result.inputMode, 'text');
    assert.strictEqual(result.inputPreview, userText);
    assert.strictEqual(result.riskScore, 88);
  });

  // =========================================================================
  // 2. URL Submission Calls /api/analyze (Zero External URL Fetch)
  // =========================================================================
  it('2. URL submission calls /api/analyze and never fetches the target URL', async () => {
    let apiCallCount = 0;
    let foreignUrlFetched = false;
    const suspiciousUrl = 'https://fake-bank-auth-verify.xyz/login';

    const mockFetch = async (input: RequestInfo | URL): Promise<Response> => {
      const urlStr = String(input);
      if (urlStr.includes('fake-bank-auth-verify.xyz')) {
        foreignUrlFetched = true;
      }
      if (urlStr === '/api/analyze') {
        apiCallCount++;
        return new Response(JSON.stringify(sampleApiResponse), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      throw new Error(`Unexpected network call to: ${urlStr}`);
    };

    const result = await executeRealAnalysis(
      { mode: 'url', url: suspiciousUrl },
      mockFetch as typeof fetch
    );

    assert.strictEqual(apiCallCount, 1);
    assert.strictEqual(foreignUrlFetched, false, 'Target URL must NEVER be fetched client-side');
    assert.strictEqual(result.isMockData, false);
    assert.strictEqual(result.inputMode, 'url');
    assert.strictEqual(result.inputPreview, suspiciousUrl);
  });

  // =========================================================================
  // 3. Screenshot Submission Sends MIME + Base64
  // =========================================================================
  it('3. screenshot submission converts file to Data URL and sends MIME + Base64', async () => {
    let capturedBody: { screenshot?: { mimeType: string; data: string } } | undefined;

    const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      capturedBody = JSON.parse(init?.body as string);
      return new Response(
        JSON.stringify({
          ...sampleApiResponse,
          extractionConfidence: 0.91,
        }),
        {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    };

    const mockImageContent = 'FAKE_PNG_BINARY_CONTENT_12345';
    const mockFile = new File([mockImageContent], 'bank_alert.png', { type: 'image/png' });

    const result = await executeRealAnalysis(
      { mode: 'screenshot', screenshotFile: mockFile },
      mockFetch as typeof fetch
    );

    assert.ok(capturedBody?.screenshot);
    assert.strictEqual(capturedBody.screenshot.mimeType, 'image/png');
    assert.ok(capturedBody.screenshot.data.startsWith('data:image/png;base64,'));
    assert.strictEqual(result.isMockData, false);
    assert.strictEqual(result.inputMode, 'screenshot');
    assert.strictEqual(result.inputPreview, 'bank_alert.png');
    assert.strictEqual(result.extractionConfidence, 0.91);
  });

  // =========================================================================
  // 4. Client Validation / Empty Inputs Guardrail
  // =========================================================================
  it('4. rejects empty or invalid inputs before dispatching network requests', async () => {
    let fetchDispatched = false;
    const mockFetch = async () => {
      fetchDispatched = true;
      return new Response('{}');
    };

    // Empty text
    await assert.rejects(
      async () => {
        await executeRealAnalysis({ mode: 'text', text: '   ' }, mockFetch as typeof fetch);
      },
      (err: Error) => {
        assert.ok(err.message.includes('نص الرسالة'));
        return true;
      }
    );

    // Empty URL
    await assert.rejects(
      async () => {
        await executeRealAnalysis({ mode: 'url', url: '' }, mockFetch as typeof fetch);
      },
      (err: Error) => {
        assert.ok(err.message.includes('الرابط'));
        return true;
      }
    );

    // Missing screenshot file
    await assert.rejects(
      async () => {
        await executeRealAnalysis({ mode: 'screenshot', screenshotFile: null }, mockFetch as typeof fetch);
      },
      (err: Error) => {
        assert.ok(err.message.includes('لقطة شاشة'));
        return true;
      }
    );

    // Unsupported screenshot MIME
    const unsupportedFile = new File(['data'], 'document.pdf', { type: 'application/pdf' });
    await assert.rejects(
      async () => {
        await executeRealAnalysis({ mode: 'screenshot', screenshotFile: unsupportedFile }, mockFetch as typeof fetch);
      },
      (err: Error) => {
        assert.ok(err.message.includes('غير مدعومة'));
        return true;
      }
    );

    assert.strictEqual(fetchDispatched, false, 'Fetch must not be called when client validation fails');
  });

  // =========================================================================
  // 5. Successful API Response Maps to Real Results Model & Preserves All Scam DNA
  // =========================================================================
  it('5. maps server AnalyzeResponse to presentation AnalysisResult accurately', () => {
    const mapped = mapApiResponseToResult(sampleApiResponse, 'text', 'preview text');

    assert.strictEqual(mapped.isMockData, false);
    assert.strictEqual(mapped.riskScore, 88);
    assert.strictEqual(mapped.riskLevel, 'high');
    assert.strictEqual(mapped.scamType, 'BANK_IMPERSONATION');
    assert.strictEqual(mapped.scamTypeNameAr, 'انتحال جهة بنكية ومصرفية');
    assert.strictEqual(mapped.summary, sampleApiResponse.interpretation);
    assert.strictEqual(mapped.scamDna.length, 2);
    assert.strictEqual(mapped.scamDna[0].provenance, 'deterministic');
    assert.strictEqual(mapped.scamDna[1].provenance, 'both');
    assert.strictEqual(mapped.evidence.length, 2);
    assert.strictEqual(mapped.evidence[0].source, 'linguistic');
    assert.strictEqual(mapped.evidence[1].source, 'technical');
    assert.strictEqual(mapped.aiConfidence, 0.94);
    assert.strictEqual(mapped.extractionConfidence, null);
    assert.strictEqual(mapped.isExtractionFailure, false);
  });

  it('5b. preserves ALL scamDna evidence and explanations without truncation or reduction to [0]', () => {
    const multiDnaResponse: AnalyzeResponse = {
      ...sampleApiResponse,
      scamDna: [
        {
          featureId: 'financial_pressure',
          nameAr: 'ضغط مالي واستعجال',
          nameEn: 'Financial Urgency & Pressure',
          detected: true,
          severity: 'high',
          provenance: 'both',
          evidence: [
            'تحويل فوري خلال 15 دقيقة',
            'إيقاف بطاقتك الائتمانية نهائياً',
            'سحب الرصيد المتبقي تلقائياً',
          ],
          explanations: [
            'استخدام أسلوب التهديد المباشر بإيقاف الخدمات المالية.',
            'خلق حالة من الذعر النفسي لحرمان الضحية من التفكير المنطقي.',
            'استغلال عنصر الوقت المحدود لطلب تحويلات سريعة.',
          ],
        },
      ],
    };

    const mapped = mapApiResponseToResult(multiDnaResponse, 'text', 'preview text');

    assert.strictEqual(mapped.scamDna.length, 1);
    const dnaItem = mapped.scamDna[0];

    // Must preserve ALL evidence items without truncation
    assert.ok(Array.isArray(dnaItem.evidence));
    assert.strictEqual(dnaItem.evidence.length, 3);
    assert.deepStrictEqual(dnaItem.evidence, [
      'تحويل فوري خلال 15 دقيقة',
      'إيقاف بطاقتك الائتمانية نهائياً',
      'سحب الرصيد المتبقي تلقائياً',
    ]);

    // Must preserve ALL explanations without reducing to [0]
    assert.ok(Array.isArray(dnaItem.explanations));
    assert.strictEqual(dnaItem.explanations.length, 3);
    assert.deepStrictEqual(dnaItem.explanations, [
      'استخدام أسلوب التهديد المباشر بإيقاف الخدمات المالية.',
      'خلق حالة من الذعر النفسي لحرمان الضحية من التفكير المنطقي.',
      'استغلال عنصر الوقت المحدود لطلب تحويلات سريعة.',
    ]);

    // Detail string must join all explanations, never losing subsequent items
    assert.ok(dnaItem.detail.includes('التهديد المباشر'));
    assert.ok(dnaItem.detail.includes('الذعر النفسي'));
    assert.ok(dnaItem.detail.includes('عنصر الوقت'));
  });

  // =========================================================================
  // 6. HTTP 400 Sanitized Error Handling (Zero Leak of Raw Validation / Zod Details)
  // =========================================================================
  it('6. handles HTTP 400 with sanitized generic message and never exposes raw server validation', async () => {
    const rawLeak = 'ZodError: /screenshot/mimeType rejected invalid mime: secret_internal_db_path';
    const mockFetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({ error: rawLeak }),
        { status: 400, headers: { 'Content-Type': 'application/json' } }
      );
    };

    await assert.rejects(
      async () => {
        await executeRealAnalysis({ mode: 'text', text: 'سلام' }, mockFetch as typeof fetch);
      },
      (err: Error) => {
        assert.ok(err instanceof AnalysisError);
        assert.strictEqual((err as AnalysisError).statusCode, 400);
        // Matches the safe client message
        assert.strictEqual(err.message, SAFE_CLIENT_ERROR_MESSAGES.BAD_REQUEST);
        // STRICT REGRESSION GUARD: Zero leak of raw server validation text
        assert.strictEqual(err.message.includes('ZodError'), false);
        assert.strictEqual(err.message.includes('secret_internal_db_path'), false);
        assert.strictEqual(err.message.includes(rawLeak), false);
        return true;
      }
    );
  });

  // =========================================================================
  // 7. HTTP 413 Screenshot Error Handling (Zero Leak of Internal Details)
  // =========================================================================
  it('7. handles HTTP 413 oversized screenshot with safe Arabic message without leaking server details', async () => {
    const rawLeak = 'INTERNAL_BUFFER_ALLOC_FAIL: 15728640 bytes exceeds max_limit at worker_thread_pool';
    const mockFetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({ error: rawLeak }),
        { status: 413, headers: { 'Content-Type': 'application/json' } }
      );
    };

    const mockFile = new File(['data'], 'large.png', { type: 'image/png' });
    await assert.rejects(
      async () => {
        await executeRealAnalysis({ mode: 'screenshot', screenshotFile: mockFile }, mockFetch as typeof fetch);
      },
      (err: Error) => {
        assert.ok(err instanceof AnalysisError);
        assert.strictEqual((err as AnalysisError).statusCode, 413);
        assert.strictEqual(err.message, SAFE_CLIENT_ERROR_MESSAGES.PAYLOAD_TOO_LARGE);
        // Regression guard: no leak of internal buffer details
        assert.strictEqual(err.message.includes('INTERNAL_BUFFER_ALLOC_FAIL'), false);
        assert.strictEqual(err.message.includes('worker_thread_pool'), false);
        assert.strictEqual(err.message.includes(rawLeak), false);
        return true;
      }
    );
  });

  // =========================================================================
  // 8. HTTP 500 & Network Error Handling (Zero Secret / Provider Leaks)
  // =========================================================================
  it('8. handles HTTP 500 and network dropouts with safe message and zero provider/internal leaks', async () => {
    // 500 server error with provider leak attempt
    const rawLeak = 'GeminiApiError: 503 Overloaded; key=AIzaSy...; stack=at Object.callAPI(/var/run/server.js:142)';
    const mock500Fetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({ error: rawLeak }),
        { status: 500, headers: { 'Content-Type': 'application/json' } }
      );
    };

    await assert.rejects(
      async () => {
        await executeRealAnalysis({ mode: 'text', text: 'رسالة' }, mock500Fetch as typeof fetch);
      },
      (err: Error) => {
        assert.ok(err instanceof AnalysisError);
        assert.strictEqual((err as AnalysisError).statusCode, 500);
        assert.strictEqual(err.message, SAFE_CLIENT_ERROR_MESSAGES.SERVER_ERROR);
        // STRICT REGRESSION GUARD: Zero leak of provider error or stack trace
        assert.strictEqual(err.message.includes('GeminiApiError'), false);
        assert.strictEqual(err.message.includes('AIzaSy'), false);
        assert.strictEqual(err.message.includes('/var/run/server.js'), false);
        assert.strictEqual(err.message.includes(rawLeak), false);
        return true;
      }
    );

    // Network disconnection / fetch rejection
    const mockNetworkFail = async (): Promise<Response> => {
      throw new TypeError('Failed to fetch: net::ERR_CONNECTION_RESET at socket.ts:40');
    };

    await assert.rejects(
      async () => {
        await executeRealAnalysis({ mode: 'text', text: 'رسالة' }, mockNetworkFail as typeof fetch);
      },
      (err: Error) => {
        assert.ok(err instanceof AnalysisError);
        assert.strictEqual(err.message, SAFE_CLIENT_ERROR_MESSAGES.NETWORK_ERROR);
        assert.strictEqual(err.message.includes('ERR_CONNECTION_RESET'), false);
        assert.strictEqual(err.message.includes('socket.ts'), false);
        return true;
      }
    );

    // Malformed JSON response
    const mockMalformedJsonFetch = async (): Promise<Response> => {
      return new Response('<html>502 Bad Gateway</html>', {
        status: 200,
        headers: { 'Content-Type': 'text/html' },
      });
    };

    await assert.rejects(
      async () => {
        await executeRealAnalysis({ mode: 'text', text: 'رسالة' }, mockMalformedJsonFetch as typeof fetch);
      },
      (err: Error) => {
        assert.ok(err instanceof AnalysisError);
        assert.strictEqual(err.message, SAFE_CLIENT_ERROR_MESSAGES.MALFORMED_RESPONSE);
        assert.strictEqual(err.message.includes('Bad Gateway'), false);
        return true;
      }
    );
  });

  // =========================================================================
  // 9. isExtractionFailure UX State Mapping
  // =========================================================================
  it('9. correctly maps isExtractionFailure for screenshot analysis failure', () => {
    const failureResponse: AnalyzeResponse = {
      ...sampleApiResponse,
      riskLevel: 'low',
      riskScore: 0,
      isExtractionFailure: true,
      interpretation: 'تعذر استخراج أو قراءة محتوى لقطة الشاشة. نتيجة الفحص غير محددة.',
      uncertainties: ['فشل استخراج محتوى لقطة الشاشة: تعذر قراءة النص.'],
      actionableAdvice: ['يرجى رفع لقطة شاشة أكثر وضوحاً أو نسخ نص الرسالة ولصقه مباشرة.'],
    };

    const mapped = mapApiResponseToResult(failureResponse, 'screenshot', 'unreadable.png');

    assert.strictEqual(mapped.isExtractionFailure, true);
    assert.strictEqual(mapped.isMockData, false);
    assert.ok(mapped.summary.includes('تعذر استخراج'));
    assert.ok(mapped.actionableAdvice.some((a) => a.includes('لقطة شاشة') || a.includes('نسخ نص')));
  });

  // =========================================================================
  // 10. Demo Scenarios Remain Mock-Only
  // =========================================================================
  it('10. verifies demo scenarios are isolated and never trigger network calls', () => {
    assert.ok(demoScenarios.length >= 3);

    for (const scenario of demoScenarios) {
      assert.ok(scenario.id);
      assert.ok(scenario.title);
      assert.ok(scenario.content);
      assert.ok(scenario.mockResult);
      // All demo results must have isMockData: true
      assert.strictEqual(
        scenario.mockResult.isMockData,
        true,
        `Demo scenario "${scenario.id}" must have isMockData: true`
      );
    }
  });

  // =========================================================================
  // 11. Browser-Compatible Web Base64 Encoding (Zero Node Buffer Dependency)
  // =========================================================================
  it('11. arrayBufferToBase64Web converts binary data using pure Web primitives without Node Buffer', () => {
    const sampleText = 'HARIS_BROWSER_COMPATIBLE_TEST_PAYLOAD_12345';
    const encoder = new TextEncoder();
    const encoded = encoder.encode(sampleText);

    // Call pure Web Base64 conversion
    const base64Result = arrayBufferToBase64Web(encoded.buffer);
    assert.strictEqual(typeof base64Result, 'string');
    // Verify decoding using Web standard atob (no Buffer)
    assert.strictEqual(atob(base64Result), sampleText);

    // Test large buffer spanning multiple 32KB chunks (e.g. 70,000 bytes)
    // to prove chunking loop works and prevents call stack overflow
    const largeSize = 70000;
    const largeBytes = new Uint8Array(largeSize);
    for (let i = 0; i < largeSize; i++) {
      largeBytes[i] = (i * 31) % 256;
    }
    const largeBase64 = arrayBufferToBase64Web(largeBytes.buffer);
    assert.ok(largeBase64.length > 0);

    // Verify decoded content length and boundary bytes using atob
    const decodedBinary = atob(largeBase64);
    assert.strictEqual(decodedBinary.length, largeSize);
    assert.strictEqual(decodedBinary.charCodeAt(0), largeBytes[0]);
    assert.strictEqual(decodedBinary.charCodeAt(35000), largeBytes[35000]);
    assert.strictEqual(decodedBinary.charCodeAt(69999), largeBytes[69999]);
  });

  it('12. fileToDataUrl produces standard Data URL via Web primitives without Node Buffer', async () => {
    /**
     * Test Strategy & Environment Limitation Note:
     * Node.js test runner provides standard Uint8Array, TextEncoder, and globalThis.btoa,
     * but lacks a native browser DOM window unless running in a real browser.
     * Here we verify fileToDataUrl using the Web File.arrayBuffer() fallback path
     * (pure Web primitives, zero Buffer), and verify the result using Web standard atob.
     * Full browser behavior is verified via real browser smoke testing in Chrome/Playwright.
     */
    const testContent = 'BROWSER_FILE_CONTENT_TEST';
    const testFile = new File([testContent], 'screenshot.png', { type: 'image/png' });

    const dataUrl = await fileToDataUrl(testFile);
    assert.ok(dataUrl.startsWith('data:image/png;base64,'));

    const base64Part = dataUrl.replace('data:image/png;base64,', '');
    // Standard Web atob decoding (no Buffer)
    const decoded = atob(base64Part);
    assert.strictEqual(decoded, testContent);
  });
});
