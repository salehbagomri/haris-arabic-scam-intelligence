'use client';

import React from 'react';
import { Globe, ShieldAlert, Info } from 'lucide-react';

interface UrlInputModeProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  isLoading?: boolean;
}

export function UrlInputMode({ value, onChange, onSubmit, isLoading = false }: UrlInputModeProps) {
  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && value.trim() && !isLoading) {
      onSubmit();
    }
  };

  return (
    <div className="haris-input-container">
      <div className="haris-url-wrapper">
        <Globe size={18} className="haris-url-icon" />
        <input
          type="url"
          className="haris-url-input ltr-text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="https://example-security-check.xyz/login"
          disabled={isLoading}
          aria-label="الرابط المشبوه"
          spellCheck={false}
          autoCapitalize="none"
        />
      </div>

      <div className="haris-input-footer">
        <div className="haris-url-hint">
          <Info size={14} />
          <span>فحص هيكلي سلبي للنطاق والعلامات دون فتح الرابط أو الاتصال بخوادمه.</span>
        </div>

        <button
          type="button"
          className="haris-primary-btn"
          onClick={onSubmit}
          disabled={!value.trim() || isLoading}
        >
          <ShieldAlert size={18} />
          <span>حلّل الآن</span>
        </button>
      </div>
    </div>
  );
}
