'use client';

import React from 'react';
import { MessageSquare, Link2, Image as ImageIcon } from 'lucide-react';
import { InputMode } from '../lib/types/analysis';

interface InputTabsProps {
  activeMode: InputMode;
  onModeChange: (mode: InputMode) => void;
  disabled?: boolean;
}

export function InputTabs({ activeMode, onModeChange, disabled = false }: InputTabsProps) {
  return (
    <div className="haris-tabs" role="tablist" aria-label="أنماط فحص المحتوى">
      <button
        type="button"
        role="tab"
        aria-selected={activeMode === 'text'}
        className={`haris-tab-btn ${activeMode === 'text' ? 'active' : ''}`}
        onClick={() => onModeChange('text')}
        disabled={disabled}
      >
        <MessageSquare size={16} />
        <span>رسالة</span>
      </button>

      <button
        type="button"
        role="tab"
        aria-selected={activeMode === 'url'}
        className={`haris-tab-btn ${activeMode === 'url' ? 'active' : ''}`}
        onClick={() => onModeChange('url')}
        disabled={disabled}
      >
        <Link2 size={16} />
        <span>رابط</span>
      </button>

      <button
        type="button"
        role="tab"
        aria-selected={activeMode === 'screenshot'}
        className={`haris-tab-btn ${activeMode === 'screenshot' ? 'active' : ''}`}
        onClick={() => onModeChange('screenshot')}
        disabled={disabled}
      >
        <ImageIcon size={16} />
        <span>صورة</span>
      </button>
    </div>
  );
}
