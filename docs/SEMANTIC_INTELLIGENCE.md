# HARIS — Semantic Intelligence & Evidence Fusion (Phase 4A)

## 1. Role of Gemini
In HARIS, Gemini is a **semantic reasoning layer**, NOT a scam judge:
- **What Gemini does**: Contextual intent analysis, psychological manipulation extraction, implicit coercion, Arabic dialect interpretation (including Yemeni colloquial phrases), Arabizi, and nuanced scam pattern identification.
- **What Gemini does NOT do**: It does not make standalone binary decisions, does not calculate numerical risk scores, and does not fetch or verify URLs.

## 2. Deterministic vs AI Evidence
- **Deterministic Evidence (`provenance: 'deterministic'`)**: Hard, mechanical rules (lexical patterns, OTP requests, structural URL anomalies, punycode, IP hosts, subdomain brand spoofing). Holds priority and cannot be erased or contradicted by AI.
- **AI Semantic Evidence (`provenance: 'ai'`)**: Contextual manipulation tactics, social engineering cues, and inferred threat features.
- Both streams are preserved with full transparency and provenance in the Scam DNA profile.

## 3. AI Confidence Semantics (`aiConfidence ≠ Risk Score`)
- `aiConfidence` (0.0 – 1.0) measures **model semantic certainty** in its linguistic interpretation.
- It is **NOT** a mathematical probability of fraud.
- `riskScore` (0 – 100) is a deterministic/heuristic evidence index ("درجة الاشتباه") computed exclusively by the fusion engine.
- AI contribution to `riskScore` is strictly bounded (capped at 15 points maximum).

## 4. Failure & Fallback Behavior
If the Gemini API is missing, times out, returns malformed JSON, or fails Zod schema validation:
- HARIS **never crashes**.
- The pipeline seamlessly falls back to 100% deterministic analysis.
- The output marks `aiAvailable: false` with the explicit fallback reason.

## 5. Privacy & Data Protection
- `GEMINI_API_KEY` is strictly server-side.
- Raw message content, credentials, and OTP values are never logged in production logs.
- Error reporting captures only error types/messages, never user inputs.

## 6. URL Safety Boundary
- URL analysis is **100% passive** (zero outbound HTTP/DNS requests).
- URLs provided to Gemini are static strings for contextual framing only; Gemini never crawls, fetches, or opens links.
