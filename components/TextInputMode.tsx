'use client';

import React from 'react';
import { ShieldAlert, Trash2 } from 'lucide-react';

interface TextInputModeProps {
  value: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  isLoading?: boolean;
}

export function TextInputMode({ value, onChange, onSubmit, isLoading = false }: TextInputModeProps) {
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      if (value.trim() && !isLoading) {
        onSubmit();
      }
    }
  };

  return (
    <div className="haris-input-container">
      <textarea
        className="haris-textarea"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="الصق هنا الرسالة التي تشك فيها (مثال: رسالة بنكية، ادعاء جائزة، طلب تحديث بيانات، أو محادثة مشبوهة)…"
        rows={6}
        disabled={isLoading}
        aria-label="نص الرسالة المشبوهة"
      />

      <div className="haris-input-footer">
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <span className="haris-char-count">
            {value.length} حرف
          </span>
          {value.length > 0 && (
            <button
              type="button"
              className="haris-secondary-btn"
              onClick={() => onChange('')}
              disabled={isLoading}
              title="مسح النص"
            >
              <Trash2 size={14} />
              <span>مسح</span>
            </button>
          )}
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
