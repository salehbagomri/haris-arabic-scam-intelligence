'use client';

import React, { useState } from 'react';
import { AlertCircle, X } from 'lucide-react';
import { Header } from '../components/Header';
import { AnalyzerHero } from '../components/AnalyzerHero';
import { InputTabs } from '../components/InputTabs';
import { TextInputMode } from '../components/TextInputMode';
import { UrlInputMode } from '../components/UrlInputMode';
import { ScreenshotInputMode } from '../components/ScreenshotInputMode';
import { DemoScenarios } from '../components/DemoScenarios';
import { AnalysisLoading } from '../components/AnalysisLoading';
import { ResultsView } from '../components/ResultsView';
import { InputMode, AnalysisResult, DemoScenario } from '../lib/types/analysis';
import { executeRealAnalysis, AnalysisError } from '../lib/services/analysisService';

export default function HomePage() {
  const [activeMode, setActiveMode] = useState<InputMode>('text');
  const [textInput, setTextInput] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [screenshotFile, setScreenshotFile] = useState<File | null>(null);

  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);

  // Trigger Real Analysis via POST /api/analyze
  const handleStartRealAnalysis = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    setAnalysisResult(null);

    try {
      const result = await executeRealAnalysis({
        mode: activeMode,
        text: textInput,
        url: urlInput,
        screenshotFile,
      });
      setAnalysisResult(result);
    } catch (err: unknown) {
      if (err instanceof AnalysisError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('حدث خطأ غير متوقع أثناء الفحص. يرجى المحاولة مرة أخرى.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  // Demo Scenarios remain strictly mock/demo without calling real Gemini or server API
  const handleSelectScenario = (scenario: DemoScenario) => {
    setErrorMessage(null);
    setActiveMode(scenario.mode);
    if (scenario.mode === 'text') {
      setTextInput(scenario.content);
    } else if (scenario.mode === 'url') {
      setUrlInput(scenario.content);
    }
    // Instantly demonstrate the pre-configured mock result
    setAnalysisResult(scenario.mockResult);
  };

  const handleModeChange = (mode: InputMode) => {
    setActiveMode(mode);
    setErrorMessage(null);
  };

  const handleReset = () => {
    setAnalysisResult(null);
    setErrorMessage(null);
    setIsLoading(false);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <Header />

      <main className="container" style={{ flex: 1, paddingBottom: 'var(--space-12)' }}>
        {!analysisResult && !isLoading && <AnalyzerHero />}

        {isLoading ? (
          <div style={{ paddingTop: 'var(--space-8)' }}>
            <AnalysisLoading />
          </div>
        ) : analysisResult ? (
          <div style={{ paddingTop: 'var(--space-6)' }}>
            <ResultsView result={analysisResult} onReset={handleReset} />
          </div>
        ) : (
          <>
            <section className="haris-analyzer-card animate-fade-in" aria-label="أداة فحص الاحتيال">
              <InputTabs
                activeMode={activeMode}
                onModeChange={handleModeChange}
                disabled={isLoading}
              />

              {errorMessage && (
                <div
                  className="haris-mock-banner animate-fade-in"
                  style={{
                    color: 'var(--danger-text)',
                    borderColor: 'var(--danger-border)',
                    background: 'var(--danger-subtle)',
                    marginBottom: 'var(--space-4)',
                  }}
                  role="alert"
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                    <AlertCircle size={18} style={{ flexShrink: 0 }} />
                    <span>{errorMessage}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setErrorMessage(null)}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: 'inherit',
                      cursor: 'pointer',
                      padding: '2px',
                    }}
                    aria-label="إغلاق رسالة الخطأ"
                  >
                    <X size={14} />
                  </button>
                </div>
              )}

              {activeMode === 'text' && (
                <TextInputMode
                  value={textInput}
                  onChange={setTextInput}
                  onSubmit={handleStartRealAnalysis}
                  isLoading={isLoading}
                />
              )}

              {activeMode === 'url' && (
                <UrlInputMode
                  value={urlInput}
                  onChange={setUrlInput}
                  onSubmit={handleStartRealAnalysis}
                  isLoading={isLoading}
                />
              )}

              {activeMode === 'screenshot' && (
                <ScreenshotInputMode
                  selectedFile={screenshotFile}
                  onFileSelect={setScreenshotFile}
                  onSubmit={handleStartRealAnalysis}
                  isLoading={isLoading}
                />
              )}
            </section>

            <DemoScenarios
              onSelectScenario={handleSelectScenario}
              disabled={isLoading}
            />
          </>
        )}
      </main>

      <footer className="haris-footer">
        <div className="container">
          <p style={{ color: 'var(--text-secondary)', marginBottom: 'var(--space-1)' }}>
            حارس (HARIS) — نظام استخبارات وتحليل الاحتيال العربي
          </p>
          <p style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            أداة وعي أمني واستدلال ذكي • الفحص السلبي لا يتصل بالروابط الخبيثة • جميع الحقوق محفوظة {new Date().getFullYear()}
          </p>
        </div>
      </footer>
    </div>
  );
}
