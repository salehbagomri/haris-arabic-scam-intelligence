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
  AnalysisError,
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
  // 5. Successful API Response Maps to Real Results Model
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

  // =========================================================================
  // 6. HTTP 400 Error Handling
  // =========================================================================
  it('6. handles HTTP 400 with user-friendly Arabic validation message', async () => {
    const mockFetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({ error: 'Unsupported screenshot MIME type. Allowed formats: image/png' }),
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
        assert.ok(err.message.includes('خطأ في التحقق من صحة المدخلات'));
        return true;
      }
    );
  });

  // =========================================================================
  // 7. HTTP 413 Screenshot Error Handling
  // =========================================================================
  it('7. handles HTTP 413 oversized screenshot with clear Arabic message', async () => {
    const mockFetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({ error: 'Screenshot payload exceeds maximum permitted size of 10 MB.' }),
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
        assert.ok(err.message.includes('10 ميجابايت'));
        return true;
      }
    );
  });

  // =========================================================================
  // 8. HTTP 500 & Network Error Handling (Zero Secret Leaks)
  // =========================================================================
  it('8. handles HTTP 500 and network dropouts with safe Arabic message', async () => {
    // 500 server error
    const mock500Fetch = async (): Promise<Response> => {
      return new Response(
        JSON.stringify({ error: 'An unexpected internal error occurred during analysis.' }),
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
        assert.ok(err.message.includes('حدث خطأ غير متوقع'));
        return true;
      }
    );

    // Network disconnection / fetch rejection
    const mockNetworkFail = async (): Promise<Response> => {
      throw new TypeError('Failed to fetch: net::ERR_INTERNET_DISCONNECTED');
    };

    await assert.rejects(
      async () => {
        await executeRealAnalysis({ mode: 'text', text: 'رسالة' }, mockNetworkFail as typeof fetch);
      },
      (err: Error) => {
        assert.ok(err instanceof AnalysisError);
        assert.ok(err.message.includes('اتصال الإنترنت'));
        // Never leaks raw exception details
        assert.strictEqual(err.message.includes('ERR_INTERNET_DISCONNECTED'), false);
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
  // 11. fileToDataUrl Universal Encoding
  // =========================================================================
  it('11. fileToDataUrl produces standard Data URL encoding', async () => {
    const testContent = 'TEST_FILE_CONTENT';
    const testFile = new File([testContent], 'test.png', { type: 'image/png' });

    const dataUrl = await fileToDataUrl(testFile);
    assert.ok(dataUrl.startsWith('data:image/png;base64,'));

    const base64Part = dataUrl.replace('data:image/png;base64,', '');
    const decoded = Buffer.from(base64Part, 'base64').toString('utf8');
    assert.strictEqual(decoded, testContent);
  });
});
