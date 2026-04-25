# Product Requirements Document — `llm_context_shield`

**Status:** Living document. Retrofitted at v0.4 to anchor the project's expanding scope.
**Owner:** John ([@gatewaynode](https://github.com/gatewaynode))
**Last reviewed:** 2026-04-25

This document describes *what* `llm_context_shield` is, *who* it serves, and *which deployment contexts* it must support. It is the source of truth for scope decisions. Phase-level *how* and *when* live in [`tasks/todo.md`](tasks/todo.md); architecture lives in [`tasks/ARCHITECTURE.md`](tasks/ARCHITECTURE.md); installation and CLI usage live in [`README.md`](README.md). This PRD links to them and does not duplicate them.

---

## 1. Vision

A general-purpose, UNIX-philosophy threat scanner for LLM context-injection attacks. The same binary and library serve every layer of an LLM stack — from a single-shot pipe filter feeding one prompt, to a long-running gateway watching thousands of concurrent sessions. The scanner reports; it never rewrites. It runs locally; nothing leaves the process unless the operator opts in. It is small, fast, deterministic, cross-platform, and embeddable.

## 2. Personas

| Persona | Description | Primary use cases |
|---|---|---|
| **Skill author** | Writes Claude Code skills, MCP servers, or agent tools that fetch external content. Wants a one-line `lcs scan -p` filter between fetch and model. | UC-1 |
| **Application developer** | Builds a Rust application (CLI tool, batch processor, internal service) that needs to scan untrusted text before passing it to an LLM. Embeds the library, customises the engine, ignores the CLI. | UC-2, UC-3 |
| **Security engineer** | Audits stored content — prompt logs, document corpora, ingested datasets — for injection attempts. Runs the tool over batches of files and reviews aggregated results. | UC-3, UC-4 |
| **Platform operator** | Runs an LLM-backed service (chatbot, agent platform, RAG endpoint, API gateway). Needs per-user threat tracking across requests and pluggable storage that survives across processes. | UC-5 |

## 3. Use Cases

The five contexts that scope this project. Every roadmap phase must trace back to one of these.

### UC-1 — Inline pipe filter

A skill or shell pipeline routes external content through `lcs scan -p` before the content reaches a model. Clean content flows through; threats block the pipe.

- **Primary user:** Skill author, application developer
- **Status:** ✅ Shipped
- **Reference implementation:** [`skill/safe-fetch.md`](skill/safe-fetch.md), [`README.md`](README.md) "Recommended workflow" section
- **Key NFR:** Latency. The scan must add negligible overhead to a `curl | model` pipeline. Single-process, single-input, no state.

### UC-2 — Single-file scan

A user or script invokes `lcs scan <file>` (or `Shield::scan(text)` from a Rust binary) to check one input. Output is consumed directly — exit codes for shell scripts, JSON for tooling, text for humans.

- **Primary user:** Application developer, security engineer
- **Status:** ✅ Shipped
- **Reference implementation:** [`README.md`](README.md) "Usage" section, [`examples/embed.rs`](examples/embed.rs)
- **Key NFR:** Determinism. Repeated scans of the same input produce byte-identical output (BTreeMap-ordered class scores; stable rule-name sorting).

### UC-3 — Multi-file batch review

A user scans many files as a related set — a downloaded corpus, a PR diff with multiple touched documents, an entire prompt directory. Per-file results are useful, but so are *group-level* aggregations: which threat classes appeared across the batch, whether suspicious patterns cluster across multiple files, what the worst-offender file is.

- **Primary user:** Security engineer, application developer
- **Status:** 📅 Roadmap — Phase 13 (scan groups)
- **Key NFR:** Aggregation. Group-level threat scoreboards and cross-input correlation must work without persistence or temporal semantics. A scan group is a one-shot snapshot.

### UC-4 — Prompt-history review

Replay a captured chat history (system prompt + N user turns + N assistant turns) through the scanner to identify which turn introduced an injection, or to detect crescendo patterns retrospectively.

- **Primary user:** Security engineer, application developer
- **Status:** 📅 Roadmap — partially Phase 13 (orderless replay), partially Phase 12 (temporal replay with crescendo detection)
- **Key NFR:** Both flavours required. Orderless replay (treat the history as a scan group) answers "is anything bad anywhere here?". Temporal replay (treat the history as an ordered session) answers "is this a multi-turn attack pattern?". The same captured history can be run through either pipeline depending on the question.

### UC-5 — WAF / API-gateway module

A long-running service (an inference gateway, a RAG ingest sidecar, a chatbot front end) embeds the library and calls it on every incoming request. State is per-user (or per-API-key, or per-conversation) and must survive across requests, processes, and restarts. Storage backend is operator-chosen along an embedded-to-decoupled scaling axis: in-memory for ephemeral / development; embedded `redb` for single-process durable deployments (no infrastructure required); Redis for multi-host deployments where session state must be shared. The backend switch is a config change, not a code change — all three implement the same `SessionStore` trait.

- **Primary user:** Platform operator
- **Status:** 📅 Roadmap — Phase 12 (session tracking with out-of-process backend)
- **Key NFR:** The session-store trait must be designed for out-of-process backends from the first sub-phase, even if only the in-memory implementation ships initially. Trait shape changes after operators are integrating against it are unacceptable.

## 4. Functional Requirements

### 4.1 Threat detection coverage

The scanner detects the categories listed in [`README.md`](README.md) "Scanner Categories" — prompt injection, instruction override, jailbreak, delimiter manipulation, data exfiltration, hidden content, refusal suppression, response steering, secret probing, context shift, ICL exploitation, coercion, refusal bypass, session protocol, and obfuscation.

Coverage is documented per category against the CrowdStrike Prompt Injection Attack Taxonomy in [`data/prompt-injection-attack-taxonomy.md`](data/prompt-injection-attack-taxonomy.md).

### 4.2 Scan engines

Three interchangeable engines, selected at build time and runtime, documented in detail in [`README.md`](README.md) "Scan Engines":

- **`simple`** — hardcoded Rust regex. Fastest. No optional features.
- **`yara`** — YARA-X (VirusTotal's pure-Rust YARA). Editable `.yar` files. Build flag `--features yara`.
- **`syara`** — SYARA-X (Super YARA), adds semantic matchers in three tiers: regex (always on), `similarity:` via local ONNX MiniLM (`--features syara-sbert`), and `llm:` via an OpenAI-compatible endpoint (`--features syara-llm`).

The library exposes the `Engine` trait as the extension point. Custom engines (see [`examples/custom_engine.rs`](examples/custom_engine.rs)) can be plugged in without modifying the library.

### 4.3 Orchestration capabilities

Capabilities that combine signals across rules, engines, scans, or sessions. These live in the orchestrator (`Shield`), not in individual engines.

| Capability | Phase | Status | What it adds |
|---|---|---|---|
| Heuristic threat scoring | 7 | ✅ Shipped | Per-class and cumulative threat accumulators. Threshold-gated rules can stay silent until cheaper rules raise suspicion. |
| Cross-rule correlation | 11 | ✅ Shipped | Rules that fire only when two findings co-occur (proximate, ordered, combined, or cross-engine). Composite scores feed back into the scoreboard. |
| Session tracking | 12 | 📅 Roadmap | Per-session history of scan summaries; rules that fire on multi-turn patterns (crescendo, frequency, spread, spike). |
| Scan groups | 13 | 📅 Roadmap | Orderless multi-input correlation. Per-input results plus group-level aggregations. |
| Confidence calibration | 14 | 📅 Roadmap | Calibrated probability estimates that combine evidence from string matches, semantic similarity, LLM verdicts, correlation, and session signals into a unified confidence score. |

### 4.4 Reporting

- **Exit codes** — `0` = clean, `1` = findings detected, `2` = error. Stable contract across all subcommands.
- **Output formats** — `text` (human-readable to stderr, summary to stdout), `json` (full report to stdout, `jq`-composable), `quiet` (exit code only).
- **Severity filtering** — `--severity low|medium|high|critical` filters before reporting.
- **Passthrough** — `lcs scan -p` writes the original input to stdout when clean, suppressing the scan summary so the content can flow through a pipeline. Optional `-o <file>` redirects to a file.

### 4.5 Configuration

Configuration is opt-in. CLI flags always override config; config always overrides built-in defaults. On first run, `lcs init` (or any `lcs scan` invocation with no config dir present) creates `~/.config/llm_context_shield/config.toml` with all options commented out.

Config sections, all optional: `[scan]`, `[rules]`, `[syara]`, `[scoring]`, `[correlation]`, and (📅 Phase 12) `[session]`, (📅 Phase 13) `[scan_group]`, (📅 Phase 14) `[confidence]`.

### 4.6 Custom rules

The `yara` and `syara` engines load user-authored rules from `$XDG_DATA_HOME/llm_context_shield/rules/{yara,syara}/`. The `correlation` engine loads custom correlation rules from a TOML path specified in `[correlation] custom_rules`.

Rule authoring is documented in [`docs/rule-authoring.md`](docs/rule-authoring.md). The simple→YARA migration guide lives at [`docs/migration-from-simple.md`](docs/migration-from-simple.md). The semantic-rule guide lives at [`docs/semantic-rules.md`](docs/semantic-rules.md).

## 5. Non-Functional Requirements

### 5.1 Performance

- **Latency.** A single-input scan on the `simple` engine is well under 100ms p99 on commodity hardware for inputs up to 1 MiB. The `yara` engine is comparable. Semantic tiers (`syara-sbert`, `syara-llm`) degrade gracefully — they add latency but only when their respective rule types are enabled.
- **Memory.** Single-process resident set is bounded by input size + rule set size + (when enabled) one MiniLM model. No unbounded growth in long-running embeddings; session storage is caller-controlled (opt-in).
- **Input size cap.** `read_input` enforces a 100 MiB cap on stdin and file input.

### 5.2 Privacy

No scan content leaves the process unless the operator has explicitly opted in to LLM-backed semantic rules (`syara-llm`). Even then, the configured endpoint is operator-chosen — it can be a fully local server (LMStudio, Ollama, vLLM) or a remote API. The default-build CLI (no LLM features) makes no network calls.

`ScanSummary` (Phase 12) and `GroupReport` (Phase 13) carry only metadata — categories, threat classes, severity histograms, scores. They do not store input text or finding details.

### 5.3 Determinism

Output across runs is byte-identical for the same input and configuration. Class scores use `BTreeMap` for alphabetical ordering. Rule iteration is stable. Exit codes are reproducible.

### 5.4 Cross-platform

Eight targets ship in the release matrix: macOS arm64, macOS x86-64, Linux x86-64 (musl), Linux aarch64 (musl), Windows x86-64 (GNU), Windows ARM64, FreeBSD x86-64, WebAssembly (WASI). OpenBSD and NetBSD build natively but are not cross-compilable. See [`README.md`](README.md) "Release Builds" for the full matrix.

### 5.5 Dependency posture

Per [`CLAUDE.md`](CLAUDE.md): never use the latest dependency version (target N-1), never use packages less than 30 days old, pin and verify hashes when possible, audit transitive dependencies on every bump.

### 5.6 Library / CLI separation

Library consumers must be able to depend on `llm_context_shield` without pulling in `clap`, `tracing-subscriber`, or `tracing-appender`. The `cli` feature is default-on for binary builds and opt-out for library consumers (`default-features = false`).

## 6. Embedding Contracts

The five use cases above translate to four concrete embedding surfaces. Each has a stable API contract from v0.4 onward.

### 6.1 CLI

Stable from v0.4. The `lcs scan` subcommand, its flags, and its three exit codes are part of the public contract. New flags may be added; existing ones do not change semantics. New output fields (in `text` and `json`) are additive.

Documented in [`README.md`](README.md) "Usage" and "Options" sections.

### 6.2 Library

Stable from v0.4 with the `Shield` builder API at the surface. Engine implementations and the `Engine` trait are stable extension points. `Send + Sync` bounds on `Engine` and (📅 Phase 12) `SessionStore` are required for multi-threaded embeddings.

Crate features:
- `cli` (default) — pulls in `clap`, `tracing-subscriber`, `tracing-appender`.
- `yara` — YARA-X engine.
- `syara` — SYARA-X engine (string-only by default).
- `syara-sbert` — adds local ONNX MiniLM similarity matching.
- `syara-classifier` — adds local ONNX classifier matching.
- `syara-llm` — adds OpenAI-compatible LLM matching (network-using).

Library consumers should use `default-features = false` and opt into only the engines they need. See [`README.md`](README.md) "Library Usage" and [`examples/embed.rs`](examples/embed.rs).

### 6.3 WASM

The `wasm32-wasip1` target ships in the release matrix. Use cases:

- In-browser scanning (via WASI runtime in browser).
- In-runtime scanning embedded in a host application that uses Wasmtime / Wasmer / WasmEdge.

Constraints:
- LLM-backed rules (`syara-llm`) are not usable in WASM today (no HTTP client in pure WASI preview-1).
- Filesystem rule discovery requires WASI preview-2 capability grants; bundled rules work without filesystem access.
- The `simple` and `yara` engines are the recommended starting points for WASM embeddings.

### 6.4 Future MCP / HTTP server

Not roadmapped yet. Captured here so future planners do not re-litigate scope: when the WAF/gateway use case (UC-5) demands a network surface beyond per-process embedding, the natural extension is a thin MCP or HTTP-server front end that wraps `Shield` and exposes `scan` and `scan_with_session` over the wire. The Phase 12 session-store trait shape is designed to anticipate this front end (out-of-process backends from day one). When the work is scheduled, it will become a new phase in [`tasks/todo.md`](tasks/todo.md).

## 7. Out of Scope / Non-Goals

The following are explicitly *not* part of this project's scope. Each appears here because someone has asked or might ask, and we want a single canonical "no" with reasoning.

- **Inline LLM rewriting / sanitisation.** The scanner reports findings and lets the caller decide what to do. It does not mutate input. Sanitisation is a different problem with its own tradeoffs (false rewrites, semantic loss); coupling it to detection would conflate two concerns.
- **Real-time streaming scans.** All scans are single-shot per input. Callers wanting to chunk a large stream must do so themselves and either submit each chunk separately or assemble a complete input first.
- **Authentication, rate-limiting, multi-tenant isolation.** These belong to the embedding host. The library does not enforce them; the CLI does not provide them.
- **Outbound LLM-output scanning.** The taxonomy targets *inputs to the model*. Scanning model outputs for harmful content, hallucinations, or data leaks is a related but distinct problem with different threat models, ground truths, and rule shapes.
- **Adversarial robustness guarantees.** No detector is bulletproof. The project commits to detecting patterns from the documented taxonomy at the documented engine tiers. It does not commit to defeating adaptive attackers who craft inputs specifically to evade these rules. Adversarial-robustness testing is captured as a future research direction in Phase 14.
- **Replacement for trust boundaries.** This is a defence-in-depth layer. It does not replace input validation, output sanitisation, principle-of-least-privilege tool design, human review, or any of the other layers an LLM-backed system needs.

## 8. Roadmap

The active phase plan, sub-phases, checklists, and review notes live in [`tasks/todo.md`](tasks/todo.md). High-level phase status as of this revision:

| Phase | Topic | Status |
|---|---|---|
| 1–6 | Foundation, engines, library packaging, releases | ✅ Shipped |
| 7 | Heuristic threat scoring | ✅ Shipped |
| 8 | High-confidence rule expansion | ✅ Shipped (8d deferred) |
| 9 | Threshold-gated behavioural rules | ✅ Shipped |
| 10 | SYARA-only semantic rules | ✅ Shipped |
| 11 | Cross-rule correlation | ✅ Shipped |
| 12 | Session-aware scanning | 📅 Next |
| 13 | Scan groups | 📅 Roadmap |
| 14 | Confidence calibration and ensemble scoring | 📅 Roadmap |

The PRD owns *what* and *why*. `tasks/todo.md` owns *how* and *when*. When a roadmap phase ships, this table moves the row from 📅 to ✅; the use-case mapping table in §3 also gets updated.

## 9. Change log

- **2026-04-25** — Initial PRD created. Retrofitted at v0.4 after Phase 11 shipped. Anchored UC-1 through UC-5; revised Phase 12 scope (session tracking only) and split out Phase 13 (scan groups) based on the use-case framing.
