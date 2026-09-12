'use client';

import React from 'react';
import { Sparkles, ArrowLeft } from 'lucide-react';
import { demoScenarios } from '../lib/demo/mockData';
import { DemoScenario } from '../lib/types/analysis';

interface DemoScenariosProps {
  onSelectScenario: (scenario: DemoScenario) => void;
  disabled?: boolean;
}

export function DemoScenarios({ onSelectScenario, disabled = false }: DemoScenariosProps) {
  return (
    <section className="haris-demo-section" aria-labelledby="demo-heading">
      <div className="haris-demo-header">
        <Sparkles size={16} color="var(--accent)" />
        <h2 id="demo-heading" style={{ fontSize: 'inherit', fontWeight: 'inherit', color: 'inherit' }}>
          جرّب حارس (سيناريوهات تجريبية جاهزة)
        </h2>
      </div>

      <div className="haris-demo-grid">
        {demoScenarios.map((scenario) => (
          <button
            key={scenario.id}
            type="button"
            className="haris-demo-card"
            onClick={() => onSelectScenario(scenario)}
            disabled={disabled}
            aria-label={`تجربة سيناريو: ${scenario.title}`}
          >
            <div className="haris-demo-top">
              <span className="haris-demo-title">{scenario.title}</span>
              <span className="haris-demo-badge">{scenario.badge}</span>
            </div>
            <p className="haris-demo-desc">{scenario.description}</p>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-1)', color: 'var(--accent-text)', fontSize: 'var(--font-xs)', fontWeight: 600, marginTop: 'var(--space-1)' }}>
              <span>فحص هذا السيناريو</span>
              <ArrowLeft size={12} />
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}
