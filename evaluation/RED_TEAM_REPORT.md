# HARIS (حارس) — Adversarial Red-Team Evaluation Report
**Report Version:** 1.0.0  
**Phase:** Phase 6B (Red-Team & Adversarial Evaluation)  
**Evaluation Date:** 2026-09-13T04:38:46.765Z  
**Pipeline Mode:** deterministic-baseline-redteam  

---

## 1. Executive Summary

This report documents the formal **Phase 6B Red-Team and Adversarial Evaluation** of the **HARIS Arabic Scam Intelligence Engine** across all **16 threat taxonomy categories** specified in `evaluation/RED_TEAM_TAXONOMY.md`.

The goal of this evaluation is to systematically stress-test and probe vulnerabilities in the approved baseline system before implementing tuning, weights adjustments, or prompt changes.

### Key Headline Metrics
- **Total Attack Corpus:** 48 cases across 16 categories.
- **Case-Level Failure Count:** **15 / 48** (**31.3%** of cases triggered at least one failure mode).
- **Cumulative Defect Instances:** **19** failure mode instances logged across failing cases.
- **Determinate False Positive Rate (FPR):** **0.0%** (0/16 determinate benign cases misclassified) | Total-Corpus FPR: 0.0% (0/19).
- **Determinate False Negative Rate (FNR):** **0.0%** (0/26 determinate evasion cases misclassified) | Total-Corpus FNR: 0.0% (0/29).
- **Indeterminate Rate (Screenshots):** **12.5%** (6/48 total) — Breakdown: Benign Indeterminate = 15.8% (3/19), Malicious Indeterminate = 10.3% (3/29).
- **Evidence Integrity Violations:** **0** recorded across all cases.
- **Scam-Type Attribution Accuracy (Determinate Scams):** **76.9%**.

---

## 2. Attack Coverage & Reproducibility Metadata

| Metadata Field | Value | Notes |
|---|---|---|
| **Evaluation Source Commit** | `f1e80fef3642ce7f26f254d07e742345f1cebd6f` | Exact Git commit of codebase during evaluation |
| **Dataset Version** | `1.0.0` | 48-case dedicated Red-Team corpus |
| **Dataset SHA-256** | `72c5a8ac8de7fdd750f94a89f1a81ff6...` | Tamper-evident cryptographic hash |
| **Runner Version** | `1.0.0` | Phase 6B Red-Team evaluator |
| **Node.js Environment** | `v24.14.0` | Runtime environment |
| **Gemini AI Configuration** | `Disabled / Offline Baseline` | Deterministic baseline mode |
| **Categories Evaluated** | `16 / 16 (100%)` | Full coverage of RED_TEAM_TAXONOMY.md |

---

## 3. Results by Taxonomy Category

| Category # | Adversarial Taxonomy Category | Total | Failed | Failure Rate | FP | FN | Evidence Violations | Avg Score |
|---|---|---|---|---|---|---|---|---|
| **1** | Brand Mention Without Impersonation | 3 | 0 | **0.0%** | 0 | 0 | 0 | 0 |
| **2** | Legitimate OTP Warnings (Polarity Inversion) | 3 | 0 | **0.0%** | 0 | 0 | 0 | 8 |
| **3** | Legitimate Urgency (Operational Deadlines) | 3 | 0 | **0.0%** | 0 | 0 | 0 | 18 |
| **4** | Benign Suspicious-Looking Domains | 3 | 0 | **0.0%** | 0 | 0 | 0 | 0 |
| **5** | Arabizi Obfuscation (Script Evasion) | 3 | 0 | **0.0%** | 0 | 0 | 0 | 87.7 |
| **6** | Unicode Confusables / Zero-Width / Tatweel | 3 | 1 | **33.3%** | 0 | 0 | 0 | 100 |
| **7** | Excessive Punctuation / Emojis | 3 | 0 | **0.0%** | 0 | 0 | 0 | 6 |
| **8** | Broken / Machine-Translated Arabic | 3 | 1 | **33.3%** | 0 | 0 | 0 | 53.7 |
| **9** | Mixed Arabic + English Concealment | 3 | 3 | **100.0%** | 0 | 0 | 0 | 38 |
| **10** | Misleading Screenshots / Layout Spoofing | 3 | 3 | **100.0%** | 0 | 0 | 0 | 0 |
| **11** | Visual Brand Resemblance (Color/Icon) | 3 | 3 | **100.0%** | 0 | 0 | 0 | 0 |
| **12** | Multiple / Decoy URLs | 3 | 0 | **0.0%** | 0 | 0 | 0 | 55.3 |
| **13** | Contradictory Evidence Fusion | 3 | 0 | **0.0%** | 0 | 0 | 0 | 93.7 |
| **14** | Scam Language Without Any URL | 3 | 0 | **0.0%** | 0 | 0 | 0 | 81.7 |
| **15** | Suspicious URL Inside Legitimate Message | 3 | 1 | **33.3%** | 0 | 0 | 0 | 39.7 |
| **16** | Long Distracting Text Containing Malicious Instructions | 3 | 3 | **100.0%** | 0 | 0 | 0 | 61 |

---

## 4. Results by Dialect

| Dialect | Description | Total Cases | Failed Cases | Failure Rate |
|---|---|---|---|---|
| **YEMENI** | Yemeni Colloquial Arabic (لهجة يمنية) | 6 | 0 | **0.0%** |
| **GULF** | Gulf Colloquial Arabic (لهجة خليجية) | 8 | 1 | **12.5%** |
| **MSA** | Modern Standard Arabic (فصحى) | 21 | 10 | **47.6%** |
| **MIXED_EN** | Bilingual Arabic + English (ثنائي اللغة) | 5 | 3 | **60.0%** |
| **ARABIZI** | Arabizi Latin Transliteration (عربيزي) | 3 | 0 | **0.0%** |
| **EGYPTIAN** | Egyptian Colloquial Arabic (لهجة مصرية) | 2 | 0 | **0.0%** |
| **BROKEN_ARABIC** | Machine-Translated / Broken Arabic (لغة مترجمة ركيكة) | 3 | 1 | **33.3%** |

---

## 5. Results by Modality

| Modality | Description | Total Cases | Failed Cases | Failure Rate |
|---|---|---|---|---|
| **TEXT** | Text Message Only (رسالة نصية فقط) | 15 | 0 | **0.0%** |
| **URL** | URL Link Only (رابط إنترنت فقط) | 3 | 0 | **0.0%** |
| **TEXT_URL** | Text + Embedded Link (نص + رابط) | 24 | 9 | **37.5%** |
| **SCREENSHOT** | Screenshot Image (لقطة شاشة مصورة) | 6 | 6 | **100.0%** |

---

## 6. False Positives Breakdown (Benign Stress Tests)

> ✅ **Zero False Positives:** None of the benign adversarial inputs were misclassified as high or suspicious risk.

---

## 7. False Negatives Breakdown (Malicious Evasion Attacks)

> ✅ **Zero False Negatives:** All malicious evasion attacks were successfully intercepted.

---

## 8. Scam DNA Failures & Feature Recall

| Feature Key | Feature Name (Arabic) | Expected Count | Detected Count | Recall |
|---|---|---|---|---|
| `urgency` | استعجال وضغط زمني | 3 | 2 | **66.7%** |
| `credential_request` | طلب بيانات اعتماد | 10 | 4 | **40.0%** |
| `otp_request` | طلب رمز التحقق OTP | 5 | 3 | **60.0%** |
| `impersonation` | انتحال صفة رسمية | 16 | 12 | **75.0%** |
| `financial_lure` | إغراء مالي وجوائز | 10 | 9 | **90.0%** |
| `suspicious_url` | رابط مشبوه وتصيد | 0 | 0 | N/A (0/0) |
| `threat_language` | تهديد وإيقاف خدمات | 11 | 6 | **54.5%** |
| `unexpected_contact` | اتصال غير متوقع | 2 | 1 | **50.0%** |
| `secrecy_pressure` | ضغط كتمان وسرية | 0 | 0 | N/A (0/0) |
| `suspicious_payment_request` | طلب دفع مالي مريب | 4 | 4 | **100.0%** |
| `action_pressure` | ضغط لاتخاذ إجراء فوري | 3 | 3 | **100.0%** |

---

## 9. Scam-Type Failures & Misattributions

- **[RED-016] تصيد بنكي بحروف مطولة عمداً (تطويل/تطعيج الكلمات)**: Expected `ACCOUNT_TAKEOVER`, but engine assigned `BANK_IMPERSONATION` (Score: 100).
- **[RED-025] تصيد Apple ID يجمع بين إشعار أمني إنجليزي وتوجيه عربي**: Expected `ACCOUNT_TAKEOVER`, but engine assigned `SOCIAL_ENGINEERING` (Score: 38).
- **[RED-026] تنبيه بنكي ثنائي اللغة يطلب تحديث KYC عبر رابط تصيد**: Expected `BANK_IMPERSONATION`, but engine assigned `SOCIAL_ENGINEERING` (Score: 38).
- **[RED-027] تصيد محفظة رقمية Metamask بطلب الكلمات المفتاحية (Seed Phrase)**: Expected `INVESTMENT_SCAM`, but engine assigned `SOCIAL_ENGINEERING` (Score: 38).
- **[RED-044] تهنئة باليوم الوطني تحتوي على رابط سحب احتيالي (لهجة خليجية)**: Expected `FAKE_PRIZE`, but engine assigned `SOCIAL_ENGINEERING` (Score: 38).
- **[RED-047] مقال علمي عن الذكاء الاصطناعي يخفي رابط استثمار وهمي عالي الربح**: Expected `INVESTMENT_SCAM`, but engine assigned `PAYMENT_SCAM` (Score: 69).

---

## 10. Evidence Integrity Failures

> ✅ **Zero Evidence Integrity Violations:** No ungrounded evidence quotes, forbidden feature triggers, or unsubstantiated high-risk verdicts occurred.

---

## 11. Highest-Severity Attack Cases (Critical & High)

### 1. [RED-025] تصيد Apple ID يجمع بين إشعار أمني إنجليزي وتوجيه عربي
- **Category:** 9. Mixed Arabic + English Concealment | **Dialect:** MIXED_EN | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `SUSPICIOUS` (Score: 38)
- **Failures:**
  - **[Medium] WRONG_SCAM_TYPE:** Misattribution of threat category: expected ACCOUNT_TAKEOVER, but attributed to SOCIAL_ENGINEERING.
  - **[High] MISSED_DNA:** Missed expected Scam DNA feature(s): [impersonation, credential_request, threat_language].

### 2. [RED-026] تنبيه بنكي ثنائي اللغة يطلب تحديث KYC عبر رابط تصيد
- **Category:** 9. Mixed Arabic + English Concealment | **Dialect:** MIXED_EN | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `SUSPICIOUS` (Score: 38)
- **Failures:**
  - **[Medium] WRONG_SCAM_TYPE:** Misattribution of threat category: expected BANK_IMPERSONATION, but attributed to SOCIAL_ENGINEERING.
  - **[High] MISSED_DNA:** Missed expected Scam DNA feature(s): [impersonation, threat_language, credential_request].

### 3. [RED-027] تصيد محفظة رقمية Metamask بطلب الكلمات المفتاحية (Seed Phrase)
- **Category:** 9. Mixed Arabic + English Concealment | **Dialect:** MIXED_EN | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `SUSPICIOUS` (Score: 38)
- **Failures:**
  - **[Medium] WRONG_SCAM_TYPE:** Misattribution of threat category: expected INVESTMENT_SCAM, but attributed to SOCIAL_ENGINEERING.
  - **[High] MISSED_DNA:** Missed expected Scam DNA feature(s): [credential_request, threat_language].

### 4. [RED-044] تهنئة باليوم الوطني تحتوي على رابط سحب احتيالي (لهجة خليجية)
- **Category:** 15. Suspicious URL Inside Legitimate Message | **Dialect:** GULF | **Modality:** TEXT_URL
- **Expected Risk:** `HIGH` | **Actual Risk:** `SUSPICIOUS` (Score: 38)
- **Failures:**
  - **[Medium] WRONG_SCAM_TYPE:** Misattribution of threat category: expected FAKE_PRIZE, but attributed to SOCIAL_ENGINEERING.
  - **[High] MISSED_DNA:** Missed expected Scam DNA feature(s): [financial_lure].


---

## 12. Recommended Fix Areas (For Phase 6C/7 — WITHOUT IMPLEMENTATION)

> [!IMPORTANT]
> In accordance with Phase 6B constraints, **NO fixes or weights modifications have been made**. These recommendations are logged for future hardening phases:

1. **Arabizi Transliteration Normalizer (Category 5):**
   - The deterministic engine relies exclusively on Arabic characters. Adding an Arabizi phonetic dictionary or transliteration preprocessor is required to capture scams written in Latin numerals (e.g. `7sabk`, `t36l`, `3shan`).

2. **Unicode Normalization & Tatweel Stripping (Category 6):**
   - Implementing NFKC canonical normalization and stripping zero-width spaces (`\u200B`) and tatweel (`ـ`) prior to regex scanning will close simple evasion loops.

3. **Multi-URL Exhaustive Inspection (Category 12):**
   - When multiple URLs are detected, ensure the worst-case malicious indicator strictly dominates rather than averaging signals or only evaluating the primary link.

4. **Phone Directing & Social Engineering Patterns (Category 14):**
   - Enhance non-URL scam detection by recognizing unsolicited phone directives combined with cash lures (`2 مليون ريال`, `صراف الكريمي`, `تواصل عبر الواتساب`).

5. **Contextual Polarity Preservation (Category 1 & 2):**
   - Continue strictly enforcing clause-level negation (`لن يطلب قط`, `إياك ومشاركة`) to guarantee zero false positives on institutional security advisories.
