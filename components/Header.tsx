'use client';

import React from 'react';
import Link from 'next/link';
import { ShieldCheck } from 'lucide-react';

export function Header() {
  return (
    <header className="haris-header" role="banner">
      <div className="container haris-header-inner">
        <Link href="/" className="haris-brand" aria-label="الرئيسية - حارس">
          <div className="haris-logo-icon">
            <ShieldCheck size={22} strokeWidth={2.2} />
          </div>
          <div className="haris-brand-text">
            <div className="haris-brand-title">
              <span>حارس</span>
              <span className="haris-brand-badge">HARIS</span>
            </div>
            <span className="haris-brand-subtitle">Arabic Scam Intelligence</span>
          </div>
        </Link>

        <div className="haris-status-indicator" aria-label="حالة النظام: الحماية الذكية مفعلة">
          <span className="haris-status-dot" aria-hidden="true" />
          <span>الحماية الذكية</span>
        </div>
      </div>
    </header>
  );
}
