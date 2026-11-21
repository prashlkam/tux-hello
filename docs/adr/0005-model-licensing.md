# ADR 0005: Model selection and licence vetting

- **Status:** Face models vetted 2026-11-21: **no existing face embedder passes.** The face way forward was **accepted** on 2026-11-21. Nothing ships before the legal review (step 4). Voice models vetted on 2026-11-21: only AASIST passes. The voice way forward was **accepted** on 2026-11-21, under the same legal-review condition.
- **Date:** 2026-11-09, face vetting and decision 2026-11-21, voice vetting 2026-11-21

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

## Voice models: findings (2026-11-21)

Every upstream was read directly. Commits are the HEAD at the time of reading; Hugging Face revisions are the model repo's current `sha`.

### Voice activity detection

| Candidate | Weights licence | Training data | Result |
|---|---|---|---|
| **Silero VAD** | **MIT** (snakers4/silero-vad `LICENSE` @ `066409f3`) | **Undisclosed.** The README only says "huge corpora that include over 6000 languages". Issues #98 (2021) and #780 (2026) asked for the training data and were closed without an answer. | ❌ Fails 3 (ToxicCandy). |

We don't need a learned VAD here. The input is a short prompted utterance in a quiet room (PLAN.md §5.4 already rejects noisy input), so an **energy and SNR endpointer written in Rust** does the job with no model at all.

### Spoken-digit recognition (the ASR check)

| Candidate | Weights licence | Training data | Result |
|---|---|---|---|
| **Vosk** `vosk-model-small-en-us-0.15` | Apache-2.0 (alphacephei.com/vosk/models) | Not documented upstream | ❌ Fails 3. |
| Vosk `vosk-model-en-us-librispeech-0.2` (Kaldi's LibriSpeech model, repackaged) | Apache-2.0 | LibriSpeech, **CC BY 4.0** (OpenSLR SLR12) | ⚠️ The data is clean, but it's 845 MB and the exact recipe of the repackaged files isn't documented. Usable as a reference, too big to ship. |
| **Whisper** (tiny / tiny.en) | MIT (openai/whisper README @ `86098128`; HF revisions `169d4a43`, `87c71024` tagged Apache-2.0) | "680,000 hours of audio … collected from the internet", not disclosed (model card) | ❌ Fails 3 (ToxicCandy). |

Ten digit words are a keyword-spotting problem, not general ASR. **Google Speech Commands** (CC BY 4.0, HF `google/speech_commands` @ `57ba463a`) contains "zero" to "nine" from thousands of consenting speakers, and LibriSpeech adds connected speech. A small digit recogniser trained on these with free code passes all five checks, and should be far smaller than any Vosk model.

### Speaker embedding

| Candidate | Weights licence | Training data | Result |
|---|---|---|---|
| **SpeechBrain ECAPA-TDNN** (`speechbrain/spkrec-ecapa-voxceleb` @ `0f99f2d0`) | Apache-2.0 | **VoxCeleb.** Only the metadata is licensed (CC BY-SA 4.0). The audio is interviews of celebrities on YouTube, owned by the uploaders, collected without the speakers' consent, and no longer distributed by Oxford. | ❌ Fails 3: scraped without consent. |
| pyannote `embedding` (@ `4db48997`), WeSpeaker ResNet34 VoxCeleb (`Wespeaker/…` @ `f0c48c29`, `pyannote/…` @ `837717dd`) | MIT / CC BY 4.0 | VoxCeleb | ❌ Same as above. |
| NVIDIA TitaNet-L (`nvidia/speakerverification_en_titanet_large` @ `0dc382f4`) | CC BY 4.0 | VoxCeleb 1+2, Fisher, Switchboard, LibriSpeech, NIST SRE | ❌ VoxCeleb, plus Fisher, Switchboard and SRE, which are paid LDC corpora that can't be redistributed. |
| WeSpeaker ResNet34 CN-Celeb (`Wespeaker/wespeaker-cnceleb-resnet34-LM` @ `ed25c1ec`) | Apache-2.0 | CN-Celeb. OpenSLR SLR82 labels it CC BY-SA 4.0, but it is 3,000 Chinese celebrities recorded "in the wild" from media Tsinghua doesn't own. | ❌ Fails 3, for the same reason as VoxCeleb. |
| 3D-Speaker models (modelscope/3D-Speaker @ `065629c3`; e.g. ModelScope `iic/speech_eres2netv2_sv_zh-cn_16k-common`, Apache-2.0) | Apache-2.0 | The 3D-Speaker dataset is recorded on devices rather than scraped, but its site licenses only the **metadata** (CC BY-SA 4.0). The audio's terms and the speakers' consent aren't stated. Some published models also mix in VoxCeleb, CN-Celeb or internal data. | ⚠️ Not proven. This is the only lead worth a follow-up question to the authors. |

Licence-clean speech with speaker labels does exist: **LibriSpeech** (CC BY 4.0, about 2,400 speakers) and **VCTK** (CC BY 4.0, HF `CSTR-Edinburgh/vctk` @ `31539806`, 110 speakers), plus **Common Voice** (CC0, many more speakers). An ECAPA model trained on these with SpeechBrain's Apache-2.0 recipe would pass. Common Voice's download terms are believed to forbid trying to identify its speakers. That needs checking, and a legal opinion on whether training a speaker *verifier* on anonymous client IDs is allowed. Without Common Voice, accuracy will be lower than the VoxCeleb models. For a method that is already second-factor only (§5.4), that's acceptable.

### Anti-spoofing

| Candidate | Weights licence | Training data | Result |
|---|---|---|---|
| **AASIST** and AASIST-L (`models/weights/AASIST.pth`, `AASIST-L.pth` in clovaai/aasist @ `a04c9863`) | **MIT**, the repository `LICENSE`, which covers the weights committed alongside the code | **ASVspoof 2019 LA.** Edinburgh DataShare record 10283/3336 lists the licence as the **Open Data Commons Attribution License**. The genuine speech is VCTK (CC BY 4.0). | ✅ **Passes checks 1–3, the only voice model that does.** Check 4 looks good: the data is free, and so is the training code. Still needs the legal review (check 5). |

The caveat with AASIST is quality, not licence: ASVspoof 2019's fakes come from 2019-era speech synthesis, and today's voice clones are much better. Plan to retrain it on newer, free spoofing data, and check that data's terms first. This doesn't change the fact that voice must stay a second factor.

## Voice: conclusion

Same result as face, with one exception. **Only AASIST can ship.** Every published VAD, digit ASR and speaker-embedding model has a permissive licence over training data that is undisclosed, scraped or paid.

Unlike face, though, **all of voice can be built licence-clean** with modest effort. **Decision (accepted 2026-11-21):**

1. **VAD:** an energy and SNR endpointer in Rust. No model.
2. **Digit ASR:** train a small keyword-spotting model on Speech Commands and LibriSpeech.
3. **Speaker embedding:** train ECAPA-TDNN on LibriSpeech and VCTK, and add Common Voice if the legal review allows it. Until then, `speechbrain/spkrec-ecapa-voxceleb` can be a `contrib` model installed by the admin, the same arrangement as the face embedder.
4. **Anti-spoofing:** ship AASIST after legal review. Retrain it on newer spoofing data later.

Voice is Phase 4, so none of this is urgent. It goes into the Phase 4 plan, together with the legal review.

## Model manifest

The model manifest (`data/models/manifest.toml`, added in Phase 2) will record, for each model, its URL, SHA-256, licence, training-data notes and vetting status (`approved`, `contrib`, or `rejected`). CI will refuse to package any model whose status is not `approved`. `contrib` models can only be installed by `tuxhello models install`.
