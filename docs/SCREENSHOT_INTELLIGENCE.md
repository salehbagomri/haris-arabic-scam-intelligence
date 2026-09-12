# HARIS — Screenshot Intelligence & Vision Evidence Pipeline (Phase 4B)

## 1. Architecture Overview
HARIS implements a multimodal screenshot intelligence pipeline where images are treated strictly as an input modality feeding into the shared core analysis engine:

```text
Screenshot
    ↓
Multimodal Vision Extraction (Gemini Multimodal)
    ↓
Extracted Text + Visual Signals + Visible Entities
    ↓
Shared Text Pipeline:
  - Arabic Normalization (normalizer.ts)
  - Passive URL Extraction & Structural Analysis (urlAnalyzer.ts)
  - Deterministic Threat Signals (signals.ts)
  - Gemini Semantic Intelligence (analyzer.ts)
    ↓
Evidence Fusion & Scam DNA Aggregation (fusion.ts)
    ↓
Comprehensive Risk Assessment (0 - 100)
```

## 2. Distinction Between OCR & Vision Interpretation
- **Extracted Content (OCR / Reading)**:
  - Verbatim text strings, visible URLs, phone numbers, CTA button text, and sender headers read from the image.
  - Feeds directly into passive deterministic rules and semantic interpretation.
- **Visual Interpretation**:
  - Layout observations, institutional visual resemblances, and design urgency cues.
  - Cautious brand language is mandatory: "The screenshot visually resembles [brand]".
  - A visual resemblance is NEVER treated as proof of authenticity or unilateral proof of fraud.

## 3. Evidence Provenance
Every piece of evidence tracks its exact origin across four transparent categories:
1. `deterministic`: Hard mechanical lexical rules and structural URL findings.
2. `ocr`: Visible entities and direct textual elements extracted from the image.
3. `ai`: Semantic manipulation tactics and visual signals inferred by Gemini.
4. `both`: Synergistic findings where deterministic and visual layers corroborate (e.g., visual brand resemblance coupled with an impersonating or suspicious domain).

## 4. Passive URL Safety Boundary
Any URL extracted from an image is routed to HARIS's 100% passive URL analyzer:
- **Zero URL fetching**: No HTTP requests are sent to the target link.
- **Zero DNS resolution**: No DNS lookups occur.
- **Zero browser navigation**: Links are analyzed strictly for structural, lexical, and cryptographic anomalies (Punycode, raw IP hosts, suspicious TLDs, subdomain brand spoofing).

## 5. Confidence Semantics
- `extractionConfidence` (0.0 – 1.0): Indicates the model's confidence in its ability to clearly read and extract content from the image. It is **NOT** a fraud probability.
- `aiConfidence` (0.0 – 1.0): Measures semantic certainty in linguistic analysis.
- `riskScore` (0 – 100): The deterministic and heuristic threat score ("درجة الاشتباه") calculated by the fusion engine. Visual cues alone have a bounded score contribution (capped at 10 points maximum).

## 6. Failure & Fallback Guarantees
- If a screenshot is corrupted, unreadable, or the vision request times out:
  - The pipeline never crashes.
  - Returns a structured fallback result.
  - If accompanying user text was provided, deterministic text analysis proceeds seamlessly.

## 7. Privacy & Security Boundaries
- **No byte persistence**: Uploaded screenshot buffers are processed in-memory and never written to disk or permanent storage.
- **No sensitive data logging**: Passwords, OTP codes, card numbers, or raw base64 payloads are never written to server logs.
- **Resource limits**: Payloads are strictly bounded to 10 MB maximum, supported MIME types are constrained (`image/png`, `image/jpeg`, `image/webp`, `image/heic`, `image/gif`), and schema strings are bounded.

## 8. Limitations & Scope
- **Dialect and Hand-drawn Fonts**: Extreme image distortions, low lighting, or stylized calligraphic scripts may degrade OCR accuracy.
- **Mocks vs Live APIs**: Unit test suites evaluate schema fidelity, grounding, URL routing, and fusion using deterministic mocks without live network calls.
