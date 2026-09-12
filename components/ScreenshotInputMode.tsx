'use client';

import React, { useRef, useState } from 'react';
import { UploadCloud, Image as ImageIcon, X, ShieldAlert, AlertCircle } from 'lucide-react';

interface ScreenshotInputModeProps {
  selectedFile: File | null;
  onFileSelect: (file: File | null) => void;
  onSubmit: () => void;
  isLoading?: boolean;
}

export function ScreenshotInputMode({
  selectedFile,
  onFileSelect,
  onSubmit,
  isLoading = false,
}: ScreenshotInputModeProps) {
  const [isDragActive, setIsDragActive] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const validateAndSetFile = (file: File) => {
    setErrorMessage(null);
    const validTypes = ['image/jpeg', 'image/png', 'image/webp'];
    if (!validTypes.includes(file.type)) {
      setErrorMessage('يرجى اختيار صورة بصيغة صالحة (PNG, JPG, أو WEBP).');
      return;
    }

    // Max 10MB
    if (file.size > 10 * 1024 * 1024) {
      setErrorMessage('حجم الصورة كبير جداً، يرجى اختيار صورة أقل من 10 ميجابايت.');
      return;
    }

    onFileSelect(file);
    const url = URL.createObjectURL(file);
    setPreviewUrl(url);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (!isLoading) setIsDragActive(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragActive(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragActive(false);
    if (isLoading) return;

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleRemove = () => {
    onFileSelect(null);
    if (previewUrl) {
      URL.revokeObjectURL(previewUrl);
      setPreviewUrl(null);
    }
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    setErrorMessage(null);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' بايت';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' ك.ب';
    return (bytes / (1024 * 1024)).toFixed(1) + ' م.ب';
  };

  return (
    <div className="haris-input-container">
      <input
        ref={fileInputRef}
        type="file"
        accept="image/png, image/jpeg, image/webp"
        style={{ display: 'none' }}
        onChange={handleFileChange}
        disabled={isLoading}
      />

      {!selectedFile ? (
        <div
          className={`haris-dropzone ${isDragActive ? 'drag-active' : ''}`}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => !isLoading && fileInputRef.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              fileInputRef.current?.click();
            }
          }}
          aria-label="منطقة رفع لقطة الشاشة"
        >
          <div className="haris-dropzone-icon">
            <UploadCloud size={28} />
          </div>
          <div className="haris-dropzone-title">
            اسحب لقطة الشاشة هنا أو انقر للاختيار
          </div>
          <div className="haris-dropzone-subtitle">
            يدعم صور المحادثات ولقطات الـ SMS وتطبيقات المراسلة (PNG, JPG حتى 10 م.ب)
          </div>
        </div>
      ) : (
        <div className="haris-preview-box">
          <div className="haris-preview-info">
            {previewUrl ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={previewUrl}
                alt="معاينة لقطة الشاشة المرفوعة"
                className="haris-preview-thumb"
              />
            ) : (
              <div className="haris-preview-thumb" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <ImageIcon size={24} />
              </div>
            )}
            <div className="haris-preview-meta">
              <span className="haris-preview-name">{selectedFile.name}</span>
              <span className="haris-preview-size">{formatFileSize(selectedFile.size)}</span>
            </div>
          </div>

          <button
            type="button"
            className="haris-secondary-btn"
            onClick={handleRemove}
            disabled={isLoading}
            aria-label="إلغاء الصورة المحددة"
          >
            <X size={14} />
            <span>إلغاء الصورة</span>
          </button>
        </div>
      )}

      {errorMessage && (
        <div className="haris-mock-banner" style={{ color: 'var(--danger-text)', borderColor: 'var(--danger-border)', background: 'var(--danger-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
            <AlertCircle size={16} />
            <span>{errorMessage}</span>
          </div>
        </div>
      )}

      <div className="haris-input-footer">
        <span className="haris-char-count">
          {selectedFile ? 'الصورة جاهزة للاستخراج والفحص' : 'بانتظار اختيار لقطة الشاشة'}
        </span>

        <button
          type="button"
          className="haris-primary-btn"
          onClick={onSubmit}
          disabled={!selectedFile || isLoading}
        >
          <ShieldAlert size={18} />
          <span>حلّل الآن</span>
        </button>
      </div>
    </div>
  );
}
