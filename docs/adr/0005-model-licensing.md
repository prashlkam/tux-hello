# ADR 0005: Model selection and licence vetting

- **Status:** Open. **Nothing in this table has been verified yet.**
- **Date:** 2026-11-09

## Why this matters

Many of the most accurate public face-recognition weights are licensed for **non-commercial research only**; InsightFace's pretrained models are a well-known example. Others were trained on datasets that have since been withdrawn or carry restrictive terms, such as MS-Celeb-1M and some VGGFace2 distributions.

Distributions cannot ship such weights, so a model with an unclear licence is a hard blocker for G3 (works on every major distro). The question is not only "what licence is on the weights file?" but also "what data was it trained on, and does that data's licence restrict the weights?"

## Vetting checklist (every model must pass)

1. The weights have an explicit licence in the upstream repository, not just a README sentence. Record the exact file and commit.
2. The licence permits redistribution and commercial use (OSI-approved or equivalent, e.g. Apache-2.0, MIT, BSD, CC0, CC-BY).
3. The training data and its licence or terms are identified. Flag anything withdrawn, scraped without consent, or non-commercial.
4. Distro-compatibility check: would Debian ftpmasters accept it into `main`? Use Debian's ML policy as the strictest bar.
5. Get a legal review for anything ambiguous before shipping.

## Candidates to evaluate in Phase 0/2

The "Believed licence" column is **from memory and must be checked against the upstream source** before anything is relied on.

| Purpose | Candidate | Believed licence (unverified) | Training-data concerns to check |
|---|---|---|---|
| Face detection | YuNet (OpenCV Zoo) | MIT | Training set terms (WIDER FACE) |
| Face embedding | SFace (OpenCV Zoo) | Apache-2.0 | Which face datasets were used; their terms |
| Face embedding | dlib ResNet face model | Public domain / CC0 | Data sources reported as including scraped celebrity images |
| Face embedding | InsightFace (ArcFace) pretrained | **Non-commercial**: likely unusable | n/a |
| Face anti-spoofing (IR) | none identified | n/a | May have to train our own on a consented IR dataset |
| VAD | Silero VAD | MIT | — |
| Speaker embedding | SpeechBrain ECAPA-TDNN (VoxCeleb) | Apache-2.0 | VoxCeleb terms |
| Spoken-digit ASR | Vosk small models | Apache-2.0 | — |
| Voice anti-spoofing | AASIST | Code MIT; weights to check | ASVspoof dataset terms |

## Fallback plan

If no face embedder passes, **train our own** on licence-clean data. This would be a consented collection campaign plus permissively licensed datasets. That would add roughly 2–3 months to Phase 2 and needs compute budget, and is PLAN.md §19, question 5.

The model manifest (`data/models/manifest.toml`, added in Phase 2) will record, for each model, its URL, SHA-256, licence, training-data notes and vetting status. CI will refuse to package any model whose status is not `approved`.
