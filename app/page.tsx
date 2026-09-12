'use client';

import React, { useState } from 'react';
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
import { mockDefaultResult } from '../lib/demo/mockData';

export default function HomePage() {
  const [activeMode, setActiveMode] = useState<InputMode>('text');
  const [textInput, setTextInput] = useState('');
  const [urlInput, setUrlInput] = useState('');
  const [screenshotFile, setScreenshotFile] = useState<File | null>(null);

  const [isLoading, setIsLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);

  // Trigger Mock Analysis flow
  const handleStartAnalysis = (customResult?: AnalysisResult) => {
    setIsLoading(true);
    setAnalysisResult(null);

    // Smooth simulated transition through the 4 stages
    setTimeout(() => {
      setIsLoading(false);
      if (customResult) {
        setAnalysisResult(customResult);
      } else {
        // Build a mock result reflecting the current mode
        const result: AnalysisResult = {
          ...mockDefaultResult,
          inputMode: activeMode,
          inputPreview:
            activeMode === 'text'
              ? textInput
              : activeMode === 'url'
              ? urlInput
              : screenshotFile?.name || 'لقطة شاشة مرفوعة',
        };
        setAnalysisResult(result);
      }
    }, 2400);
  };

  const handleSelectScenario = (scenario: DemoScenario) => {
    setActiveMode(scenario.mode);
    if (scenario.mode === 'text') {
      setTextInput(scenario.content);
    } else if (scenario.mode === 'url') {
      setUrlInput(scenario.content);
    }
    // Instantly demonstrate the scenario result
    handleStartAnalysis(scenario.mockResult);
  };

  const handleReset = () => {
    setAnalysisResult(null);
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
                onModeChange={setActiveMode}
                disabled={isLoading}
              />

              {activeMode === 'text' && (
                <TextInputMode
                  value={textInput}
                  onChange={setTextInput}
                  onSubmit={() => handleStartAnalysis()}
                  isLoading={isLoading}
                />
              )}

              {activeMode === 'url' && (
                <UrlInputMode
                  value={urlInput}
                  onChange={setUrlInput}
                  onSubmit={() => handleStartAnalysis()}
                  isLoading={isLoading}
                />
              )}

              {activeMode === 'screenshot' && (
                <ScreenshotInputMode
                  selectedFile={screenshotFile}
                  onFileSelect={setScreenshotFile}
                  onSubmit={() => handleStartAnalysis()}
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
