# ADR 0004: ML inference runtime and how it is shipped

- **Status:** Accepted. Distro availability still needs checking; see Follow-ups.
- **Date:** 2026-11-09

## Context

The face and voice backends run small neural networks: a detector, a liveness/anti-spoof model, an embedder and a VAD. We need:

- fast inference on CPU, with optional acceleration (OpenVINO, CUDA, ROCm, NPUs);
- a runtime that distributions can package without vendoring hundreds of MB.

## Decision

1. **Primary runtime: ONNX Runtime through the `ort` crate**, built with **dynamic loading** (`load-dynamic`).
   - The backend `dlopen`s `libonnxruntime.so` at startup. A missing library is reported as "face/voice unavailable", not as a crash.
   - The distro's own ONNX Runtime package is used where one exists.
   - Where none exists, `tuxhello-face` and `tuxhello-voice` ship a bundled build under `/usr/lib/tuxhello/`.
2. **Fallback runtime: `tract`** (pure Rust, MIT/Apache). It is used when ONNX Runtime can't be loaded and for architectures without ONNX Runtime builds. It is slower, but has no native dependency.
   - Every model we ship must pass a CI check that it loads and gives matching outputs (within tolerance) in **both** runtimes.
3. **No OpenCV.** Image pre-processing (resize, alignment, normalisation) is done in Rust. OpenCV is a heavy dependency and its build options differ from distro to distro.
4. **Models are installed under `/usr/share/tuxhello/models/` with a `SHA256SUMS` manifest.** The daemon verifies the hashes at start-up. Models are never downloaded at runtime.

## Consequences

- The daemon itself never links ONNX Runtime. Only the face and voice backend processes load it, inside their sandbox.
- Two runtimes double the test matrix for models. We accept this to keep the project portable.

## Follow-ups (Phase 2)

- Confirm the ONNX Runtime package names and versions on Arch, Debian/Ubuntu, Fedora, openSUSE, NixOS and Alpine. This hasn't been checked yet; record the results here.
- Benchmark `ort` against `tract` on the chosen models; latency targets are in PLAN.md §5.2.
