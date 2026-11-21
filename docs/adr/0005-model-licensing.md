# ADR 0005: Model selection and licence vetting

- **Status:** Face models vetted 2026-11-21: **no existing face embedder passes.** The way forward below was **accepted** on 2026-11-21. Nothing ships before the legal review (step 4). Voice models are not vetted yet.
- **Date:** 2026-11-09, face vetting and decision 2026-11-21

## Why this matters

Many of the most accurate public face-recognition weights are licensed for **non-commercial research only**; InsightFace's pretrained models are a well-known example. Others were trained on datasets that have since been withdrawn or carry restrictive terms, such as MS-Celeb-1M and some VGGFace2 distributions.

Distributions cannot ship such weights, so a model with an unclear licence is a hard blocker for G3 (works on every major distro). The question is not only "what licence is on the weights file?" but also "what data was it trained on, and does that data's licence restrict the weights?"

## Vetting checklist (every model must pass)

1. The weights have an explicit licence in the upstream repository, not just a README sentence. Record the exact file and commit.
2. The licence permits redistribution and commercial use (OSI-approved or equivalent, e.g. Apache-2.0, MIT, BSD, CC0, CC-BY).
3. The training data and its licence or terms are identified. Flag anything withdrawn, scraped without consent, or non-commercial.
4. Distro-compatibility check: would Debian ftpmasters accept it into `main`? Use Debian's ML policy as the strictest bar.
5. Get a legal review for anything ambiguous before shipping.

On check 4: Debian's draft [ML-Policy](https://salsa.debian.org/deeplearning-team/ml-policy) calls a model with a free licence but unknown or non-free training data a **"ToxicCandy"** model, and says neither ToxicCandy nor non-free models may enter `main`. The draft hasn't been formally adopted, but it is the bar Debian's deep-learning team uses, so we use it too. Under it, **a permissive licence on the weights is not enough. The training data has to be free as well.**

## Face models: findings (2026-11-21)

Every upstream was read directly. Commits are the HEAD at the time of reading.

### Detection

| Candidate | Weights licence (file @ commit) | Training data | Result |
|---|---|---|---|
| **YuNet** (OpenCV Zoo `face_detection_yunet_2023mar.onnx`, also `_2026may`) | **MIT**, `models/face_detection_yunet/LICENSE` @ opencv/opencv_zoo `48b10fa5`. Training code: BSD-3-Clause, ShiqiYu/libfacedetection.train @ `dca340aa` | **WIDER FACE**, whose homepage gives its licence as **CC BY-NC-ND** | ⚠️ Checks 1–2 pass. **Fails 3–4**: trained on non-commercial, no-derivatives data, so ToxicCandy under Debian's bar. The training code *is* free, so we can retrain it (see below). |
| Ultra-Light-Fast-Generic-Face-Detector-1MB | MIT (repo licence) @ `dffdddda` | WIDER FACE (with RetinaFace's cleaned labels) | ❌ Same problem as YuNet, and YuNet is better. |
| SCRFD / RetinaFace (InsightFace) | Non-commercial (see InsightFace below) | WIDER FACE | ❌ |

### Embedding (recognition)

| Candidate | Weights licence (file @ commit) | Training data | Result |
|---|---|---|---|
| **SFace** (OpenCV Zoo `face_recognition_sface_2021dec.onnx`, MobileFaceNet) | **Apache-2.0**, `models/face_recognition_sface/LICENSE` @ opencv/opencv_zoo `48b10fa5` | **Undocumented.** The SFace paper and zhongyy/SFace use CASIA-WebFace, VGGFace2 and MS-Celeb-1M. All three are research-only, and MS-Celeb-1M was withdrawn by Microsoft. Asked in opencv_zoo issues #124 (2023; a maintainer said they didn't know and closed it), #313, #318, #322, #323 and zhongyy/SFace#9: none answered. A maintainer's only reply (#318) was that the Apache-2.0 licence "should be clear enough". | ❌ **Fails 3–4.** The licence is permissive, but the training data is unknown and every possible source is non-free. ToxicCandy by definition. |
| dlib ResNet (`dlib_face_recognition_resnet_model_v1.dat`) | CC0-1.0 (repo licence) @ davisking/dlib-models `fd81b630` | The README says: FaceScrub, the VGG Face dataset, and "a large number of images I scraped from the internet" | ❌ Fails 3: research-only data plus scraped images. (The same repo's 68-point landmark model carries an explicit "can't be used in a commercial product" note from the dataset's creators.) |
| Taguchi dlib model | MIT (repo licence) | 6.5 M faces from "publicly available datasets, as well as some collected from the internet" | ❌ Fails 3 for the same reason. |
| InsightFace / ArcFace (`buffalo_l` and others) | Code MIT. The README (@ `c6c3af7b`) says trained models are "for non-commercial research purposes only"; recognition packs need a paid licence | MS1MV2/3, Glint360K, WebFace | ❌ Fails 2. |
| EdgeFace (Idiap) | Code BSD-3-Clause (otroshi/edgeface @ `ba955538`). **Weights CC-BY-NC-SA-4.0** on Hugging Face (`Idiap/EdgeFace-Base` @ `2944a63d`, `-S-GAMMA`, `-XS-GAMMA`) | WebFace (research-only) | ❌ Fails 2. Note the trap: the GitHub licence is BSD, the weights are not. |
| AdaFace | Code MIT @ mk-minchul/AdaFace `c60eaa78`. Weights on Google Drive, no licence file | CASIA-WebFace, WebFace4M, MS1MV2/3 | ❌ Fails 1 and 3. |
| FaceNet (facenet-pytorch) | Code MIT @ `787da061`. Weights from davidsandberg/facenet | VGGFace2, CASIA-WebFace | ❌ Fails 3. |
| `tropos-labs/eigen-face` (Hugging Face) | MIT tag only. The model card is empty, apart from the licence tag | Unknown | ❌ Fails 3. Found while looking for claimed "synthetic-only" models; it can't be verified. |

### Anti-spoofing (liveness)

| Candidate | Weights licence | Training data | Result |
|---|---|---|---|
| MiniFASNet (minivision-ai/Silent-Face-Anti-Spoofing) | Apache-2.0 (repo licence) @ `b6d5f04a` | Undocumented (the company's own data) | ❌ Fails 3, and it is RGB-only, which our design treats as low assurance anyway. |
| IR texture classifier | none found | n/a | We'll have to train our own on a consented IR dataset, as already planned. |

### Synthetic training data

Synthetic face datasets are the usual suggestion for licence-clean training, but the ones checked aren't clean either. **DigiFace-1M** (microsoft/DigiFace1M) is "non-commercial research" only. Face generators used for synthetic datasets, such as those behind DCFace and IDiff-Face, are generally trained on real face datasets themselves. Those weren't checked one by one here; check them before relying on any of them. Synthetic data is **not** a shortcut unless both the generator and its training data are free.

## Conclusion

**No published face embedder can ship in a distribution's main archive.** Every candidate either has a non-commercial licence on the weights, or a permissive licence over training data that is non-free or unknown. SFace, the model PLAN.md §5.2 names, is in the second group, and nobody upstream will say which.

Detection is easier. YuNet's architecture and training code are free (BSD-3-Clause), and **Open Images V7** has a boxable `Human face` class (`/m/0dzct`) with annotations under CC BY 4.0 and images listed as CC BY 2.0. Google doesn't guarantee each image's licence, so the image list must be filtered by the per-image licence metadata. Retraining YuNet on that is a small job: the model has under 100 k parameters, and one consumer GPU can train it in hours.

## Decision: the way forward (accepted 2026-11-21)

1. **Detector: retrain YuNet on Open Images faces ourselves.** Use the upstream BSD-3-Clause training code, keep only images whose recorded licence is CC BY 2.0, and publish the image-ID list, the training config and the checksums. That passes all five checks and is reproducible, which Debian's ML policy asks for.
2. **Embedder, near term: split the models off from the code.** `tuxhello-face` ships with **no** embedding model. Instead, an explicit, root-only `tuxhello models install sface` command downloads a pinned file, checks its SHA-256, and shows the licence and training-data caveats first. The admin has to accept them. This is what Howdy does with dlib's models, and it fits Debian `contrib`. It amends ADR 0004 point 4 ("models are never downloaded at runtime"): the daemon still never downloads anything, but an admin can explicitly install a model.
3. **Embedder, long term: train our own** (PLAN.md §19, question 5) on consented data, or on synthetic data from a generator whose own training data is free. This is the only route to a face embedder in `main`. Estimate it as its own project of 2–3 months, plus compute and a consent process.
4. **Legal review (check 5) before anything ships**, whichever option is chosen. This includes the question of whether weights trained on CC BY-NC-ND data are themselves "derivatives". This ADR records facts, not legal advice.

Meanwhile, Phase 2's capture, alignment, quality gate and matching code can go ahead against any ONNX model. The model is a replaceable input.

## Voice models (not vetted yet)

The "Believed licence" column is **from memory and must be checked against the upstream source**, the same way as the face models above.

| Purpose | Candidate | Believed licence (unverified) | Training-data concerns to check |
|---|---|---|---|
| VAD | Silero VAD | MIT | — |
| Speaker embedding | SpeechBrain ECAPA-TDNN (VoxCeleb) | Apache-2.0 | VoxCeleb terms (VoxCeleb is built from celebrity YouTube videos, so expect the same problem as the face datasets) |
| Spoken-digit ASR | Vosk small models | Apache-2.0 | — |
| Voice anti-spoofing | AASIST | Code MIT; weights to check | ASVspoof dataset terms |

## Model manifest

The model manifest (`data/models/manifest.toml`, added in Phase 2) will record, for each model, its URL, SHA-256, licence, training-data notes and vetting status (`approved`, `contrib`, or `rejected`). CI will refuse to package any model whose status is not `approved`. `contrib` models can only be installed by `tuxhello models install`.
