# Proxide — Architecture Decision Records (ADR)

This document records the core architectural decisions, trade-offs, guardrails, and authoritative references for **Proxide**. Every ADR maps directly to enforcement rules in [CODING_STANDARDS.md](../CODING_STANDARDS.md), Go-unique runtime safeguards in [go-pitfalls.md](go-pitfalls.md), and execution tasks in [01_PLAN.md](01_PLAN.md).

---

## Decision Matrix

| ADR | Area | Selected Approach | Status |
| :--- | :--- | :--- | :--- |
| [ADR 1](#adr-1-universal-coding-standards-go-idiom-adaptation-and-separate-go-pitfalls-registry) | Code Hygiene & Standards | Universal pillars (pure transforms, immutability, CQS, zero magic numbers) + Go idiom rules + separate Go pitfalls catalog | Accepted |
| [ADR 2](#adr-2-go-stdlib-first-runtime-over-kotlinjvm-and-rust-for-the-proxy-daemon) | Language & Runtime | Go 1.27 (`net/http`, `crypto/tls`, `crypto/x509`, goroutines), stdlib-first + minimal vetted deps (`singleflight`, `websocket`, `go/packages`) | Accepted |
| [ADR 3](#adr-3-decoupled-proxy-daemon-and-inspector-client-over-loopback-rest-and-websocket-stream) | System Shape & Event Contract | Split `proxided` daemon from thin inspector clients (`proxide`) over loopback REST + WebSocket/SSE & immutable `CaptureEvent`s | Accepted |
| [ADR 4](#adr-4-dual-network-exposure-and-security-boundary) | Network Exposure & Trust | LAN-bound proxy (`0.0.0.0:8080`) & read-only portal (`0.0.0.0:8081`) strictly separated from loopback-only Control API (`127.0.0.1:9090`) | Accepted |
| [ADR 5](#adr-5-lan-listener-source-ip-normalization-controller-tagging-and-client-registry) | LAN Plumbing & Client Tagging | `0.0.0.0` / `--iface` listener, `netip.Addr.Unmap()`, `X-Proxide-Client` tag extraction, friendly aliases & best-effort ARP/MAC lookup | Accepted |
| [ADR 6](#adr-6-dynamic-mitm-tls-architecture-and-passthrough-detection) | Dynamic MITM TLS & CA | Persistent ECDSA P-256 Root CA (`0700`/`0600`), short-lived SAN leaf certs (`7d`, `<= 397d`, `-5m`), LRU (`2048`) + `singleflight`, passthrough + pin detection | Accepted |
| [ADR 7](#adr-7-local-setup-portal-user-agent-classifier-and-multi-format-ca-downloads) | Device Onboarding Portal | `embed.FS` portal on `0.0.0.0:8081` & `http://proxide.local`, pure UA classifier, `.pem`/`.cer`/`.der`/`.crt` CA endpoints & fingerprint | Accepted |
| [ADR 8](#adr-8-target-device-strategy-and-known-constraints) | Device Support & Scope | First-class Fire TV, Android TV, Android, iOS, tvOS & local controllers; best-effort Roku & cert-pinned apps via passthrough | Accepted |
| [ADR 9](#adr-9-bounded-capture-store-non-blocking-event-fan-out-and-manipulation-pipeline) | Store, Fan-Out & Rewrites | Dual-bounded ring buffer (`5000` flows / `256 MiB`), `1 MiB` body capture cap, drop-oldest `internal/bus`, root-jailed Map Local & header/body rewrite | Accepted |
| [ADR 10](#adr-10-layered-verification-strategy-and-architecture-fitness-tests) | Testing, Fitness & Governance | `go test -race ./...`, native `Fuzz*` targets, loopback TLS MITM E2E tests, `go/packages` fitness suite, `golangci-lint`, pre-commit hook | Accepted |

---

## ADR 1: Universal Coding Standards, Go Idiom Adaptation, and Separate Go Pitfalls Registry

### Status
Accepted

### Context
Contributors moving from Kotlin Multiplatform / Swift / PostgreSQL projects (such as Portfolio) into Go bring strong habits around immutability, Command-Query Separation, and Functional Core / Imperative Shell, yet risk either fighting Go idioms (e.g., over-engineering generic functional chain wrappers) or hitting subtle Go-specific traps (slice aliasing, `defer` scoping, `net/http` defaults, `crypto/tls` quirks). Mixing language-specific footguns into universal architectural rules dilutes both.

### Decision
1. Codify **universal, language-agnostic standards** in [CODING_STANDARDS.md](../CODING_STANDARDS.md) Part I & Part V: pure transformations, immutability across boundaries, CQS (`GET` 100% read-only; pure core vs. I/O shell), zero magic numbers/strings, and focused helper extraction.
2. Document **idiomatic Go adaptation**: express pure transformations as concise, zero-I/O Go functions returning newly allocated values alongside `slices` and `maps` stdlib helpers rather than forcing fluent chain wrappers over `(T, error)`.
3. Isolate **all Go-specific language, runtime, stdlib, and concurrency hazards** inside a dedicated living registry at [go-pitfalls.md](go-pitfalls.md) (`GP-01`–`GP-34`), cross-referenced from Part VI of `CODING_STANDARDS.md`.

### Trade-offs & References
- **Trade-off:** Maintaining two cross-referenced docs requires discipline to keep universal vs. Go-unique issues cleanly separated, in return for portable architectural standards and a zero-noise Go onboarding checklist.
- Martin Fowler — [CommandQuerySeparation](https://martinfowler.com/bliki/CommandQuerySeparation.html) and [Value Object](https://martinfowler.com/bliki/ValueObject.html).
- Gary Bernhardt — [Functional Core, Imperative Shell](https://www.destroyallsoftware.com/screencasts/catalog/functional-core-imperative-shell).
- Go Team — [Effective Go](https://go.dev/doc/effective_go) and [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments).

---

## ADR 2: Go Stdlib-First Runtime Over Kotlin/JVM and Rust for the Proxy Daemon

### Status
Accepted

### Context
Proxide is a long-running local developer utility daemon bridging LAN smart TVs, mobile devices, and local automation controllers with dynamic TLS interception, live traffic streaming, and HTTP manipulation. We evaluated Kotlin/JVM (like Portfolio's backend), Rust, and Go (`go1.27.4`).

### Decision
- Adopt **Go 1.27+** as the sole implementation language for both the proxy daemon (`cmd/proxided`) and reference CLI/TUI inspector (`cmd/proxide`).
- Follow a **stdlib-first** dependency discipline built on `net/http`, `crypto/tls`, `crypto/x509`, `net/netip`, `log/slog`, `embed`, `slices`, `maps`, `sync/atomic`, and `testing.F`.
- Permit only three tightly scoped external dependencies in core plumbing:
  1. `golang.org/x/sync/singleflight` (leaf-cert signing deduplication).
  2. `github.com/coder/websocket` (clean context-aware WebSocket fan-out for the local inspector API).
  3. `golang.org/x/tools/go/packages` (test-only dependency for automated `internal/archtest` boundary enforcement).

### Trade-offs & References
- **Why not Kotlin/JVM:** Running a background LAN proxy daemon on the JVM introduces ~150–300 MB baseline RSS, warmup latency, and heavier desktop packaging compared to a single statically compiled Go binary with ~15–25 MB baseline memory.
- **Why not Rust:** Rust yields fine-grained memory control at the cost of slower initial iteration around async TLS handshake interception, `rustls`/`hyper` ergonomics, and multi-device flow plumbing—delaying the core goal of rapid iteration on device onboarding and inspection UX.
- **Trade-off:** Go relies on disciplined goroutine ownership and garbage collection rather than Rust's compile-time borrow checker; Proxide mitigates this via mandatory `go test -race ./...`, bounded buffers (`ADR 9`), and [go-pitfalls.md](go-pitfalls.md).
- Go Standard Library — [`net/http`](https://pkg.go.dev/net/http), [`crypto/tls`](https://pkg.go.dev/crypto/tls), [`crypto/x509`](https://pkg.go.dev/crypto/x509).

---

## ADR 3: Decoupled Proxy Daemon and Inspector Client Over Loopback REST and WebSocket Stream

### Status
Accepted

### Context
During initial development, a CLI/TUI view is fastest to build and verify. Over time, Proxide should support richer web or desktop inspector UIs (potentially even SwiftUI, Compose, or browser-based views) without touching TLS handshakes, socket tunneling, or CA handling.

### Decision
- Split the codebase and runtime responsibilities cleanly into two binaries:
  - **`cmd/proxided`:** Headless proxy engine, Root CA / SNI leaf signer, LAN Setup Portal, bounded flow ring buffer, manipulation engine, and local Control/Inspector API.
  - **`cmd/proxide`:** Thin CLI/TUI inspector client plus `adb` proxy helper subcommands communicating **exclusively** over the loopback REST + WebSocket/SSE API (`127.0.0.1:9090`).
- Enforce at compile/test time (`internal/archtest`) that `cmd/proxide` imports only `internal/model` (wire contracts) and never imports `internal/proxy`, `internal/ca`, `internal/tlsmitm`, `internal/portal`, or `internal/store`.
- Emit every captured HTTP/HTTPS/WebSocket/SSE interaction as an immutable, self-contained `CaptureEvent` struct containing `id`, `client`, `protocol`, `request`, `response`, `stream_frames`, `timing`, `tls`, and `manipulations`.

### Trade-offs & References
- **Trade-off:** Serializing flow snapshots over loopback JSON/WebSocket adds modest encoding overhead vs. in-process memory pointers, in exchange for total UI replaceability, independent client crashes having zero effect on live LAN proxying, and clean cross-language UI extensibility.
- IETF RFC 6455 — [The WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455).
- WHATWG — [Server-Sent Events](https://html.spec.whatwg.org/multipage/server-sent-events.html).

---

## ADR 4: Dual Network Exposure and Security Boundary

### Status
Accepted

### Context
Target devices on the local network (Fire TV, Android TV, iOS, tvOS) must reach the proxy port and download the Root CA certificate over the LAN. However, exposing traffic history, full captured headers/bodies (`Authorization`, `Cookie`), rewrite rule mutation endpoints, or the Root CA private key on `0.0.0.0` would let any untrusted LAN device intercept or manipulate other devices' flows.

### Decision
Enforce a strict **two-zone network boundary**:
1. **LAN-Reachable Zone (`0.0.0.0:8080` Proxy, `0.0.0.0:8081` & `http://proxide.local` Portal):**
   - Proxy listener accepts HTTP proxy traffic and `CONNECT` requests only.
   - Setup Portal is **100% read-only (`GET` only)** and serves **only** device onboarding pages, SHA-256 fingerprint, and public Root CA files (`.pem`, `.cer`, `.der`, `.crt`). It holds zero access to `internal/store`, `internal/rewrite`, or `ca-key.pem` raw bytes.
2. **Loopback-Only Zone (`127.0.0.1:9090` Control & Inspector API):**
   - Bound strictly to `127.0.0.1` by default. Serves capture queries, rule CRUD, client aliasing, passthrough configuration, and live WebSocket/SSE event streams.
   - Any explicit user override to listen beyond loopback must fail startup unless an explicit authentication token/opt-in flag is provided.
3. **Typed Error Envelope (`ApiError`):** All API failures return structured `ApiError` JSON (`code`, `message`, `trace_id`, optional `field_errors`), stripping internal paths/stacks outside explicit `--debug` mode.

### Trade-offs & References
- **Trade-off:** Remote inspectors on a second workstation must SSH-tunnel or explicitly configure authenticated API access rather than connecting unauthenticated over the LAN, preventing accidental credential/traffic leakage on shared Wi-Fi networks.
- OWASP — [API Security Top 10](https://owasp.org/www-project-api-security/) and [Localhost Binding Guidance](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html).

---

## ADR 5: LAN Listener, Source-IP Normalization, Controller Tagging, and Client Registry

### Status
Accepted

### Context
Inspecting multiple devices simultaneously (a Fire TV stick, an iPhone, an Android tablet, and two local Go/Python automation controllers on `localhost` or LAN) becomes unusable if flows cannot be filtered reliably per device. Dual-stack OS sockets (`::ffff:192.168.x.y`), dynamic DHCP IPs, and multiple local controllers sharing `127.0.0.1` create immediate attribution ambiguity.

### Decision
- **Configurable LAN Binding:** Default `--listen 0.0.0.0:8080`, plus an `--iface <name>` helper flag resolving a specific LAN IPv4/IPv6 interface address so users on multi-homed Macs/Linux hosts can advertise the exact Wi-Fi IP to TVs/phones.
- **Canonical IP Normalization:** Parse every `net.Conn.RemoteAddr()` via `netip.ParseAddrPort` and strip IPv4-mapped IPv6 wrappers with `.Addr().Unmap()` before client lookup or tagging.
- **Controller Custom Tagging (`X-Proxide-Client`):** Extract an optional tag header (`DefaultClientTagHeader = "X-Proxide-Client"`, configurable) from incoming HTTP/HTTPS requests so multiple local scripts or test runners sharing one host IP tag themselves cleanly (e.g., `X-Proxide-Client: playback-controller-a`). Strip this internal tag header before forwarding upstream by default.
- **Friendly Names & Best-Effort MAC Lookup (`internal/clientreg`):** Allow operator-assigned friendly aliases per IP/tag via the loopback API (`PUT /api/v1/clients/{ip}`) and perform non-privileged, best-effort MAC address enrichment from OS neighbor/ARP caches without ever requiring root or raw packet capture.

### Trade-offs & References
- **Trade-off:** Best-effort ARP/neighbor lookups may yield empty MACs for `localhost` clients or across routed VLANs, so `ClientIdentity.IP` + optional `Tag` remain the canonical keys while `MAC` and `FriendlyName` act as optional enrichment.
- Go Standard Library — [`net/netip.Addr.Unmap`](https://pkg.go.dev/net/netip#Addr.Unmap).

---

## ADR 6: Dynamic MITM TLS Architecture and Passthrough Detection

### Status
Accepted

### Context
Modern TVs and mobile platforms enforce strict X.509 validation rules: Apple iOS/tvOS/macOS reject leaf certificates exceeding 398 days (`HT210176`), modern Android/Go/BoringSSL reject certificates without Subject Alternative Names, and streaming apps aggressively open parallel HTTPS connections to the same CDN hostnames. Meanwhile, cert-pinned apps fail TLS handshakes immediately after receiving a synthetic leaf certificate.

### Decision
- **Persistent Disk Root CA (`internal/ca`):** Generate once on startup inside a `0700` directory with `0600` private key (`ca-key.pem`, atomic temp write + `os.Rename`) and `0644` certificate (`ca-cert.pem`). Default to **ECDSA P-256** (`elliptic.P256()`) for sub-millisecond leaf generation and broad support on iOS 13+, tvOS, Android 7+, FireOS, and modern controllers; provide an optional RSA-2048 config flag for legacy clients.
- **Compliant On-The-Fly Leaf Signing:** Inside `tls.Config.GetCertificate`, generate leaf certs using:
  - `NotBefore = now - 5m` (`LeafClockSkewBackdate`) for minor device clock drift.
  - `NotAfter = now + 7d` (`DefaultLeafCertTTL`), clamped strictly `<= 397d` (`MaxAppleLeafCertTTL`).
  - Mandatory SANs (`DNSNames` for hostnames; `IPAddresses` when the target host is an IP literal).
  - `ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}` and unique positive 128-bit `crypto/rand` serial numbers.
- **Bounded LRU + `singleflight` Cache (`internal/tlsmitm`):** Cache `*tls.Certificate` instances in a bounded in-memory LRU (`DefaultCertCacheSize = 2048`) keyed by normalized SNI/host, using `golang.org/x/sync/singleflight` so concurrent device connections sign once per cache miss without holding a cache-wide lock during crypto operations.
- **ALPN & Upstream TLS Discipline:** Pin client-side `NextProtos` strictly to the protocol handled by the MITM reader (`http/1.1` initially, matching `ADR 6` / `GP-31`), verify upstream certificates against system roots by default (`InsecureSkipVerify: false`), and use `http.Transport.RoundTrip` with `DisableCompression: true`.
- **Passthrough Allowlist & Pin Detection:** Support per-host and per-client TLS passthrough rules (`CONNECT` direct TCP tunnel) plus tracking consecutive client TLS handshake alerts immediately after ServerHello (`pin_suspected = true`) to guide users toward passthrough.

### Trade-offs & References
- **Trade-off:** Using a 7-day leaf TTL requires regenerating cached leaves if the daemon runs continuously for over a week (handled automatically by storing expiry metadata alongside cached LRU entries and evicting near-expiry certs), in exchange for staying well below Apple's 398-day ceiling.
- Apple Support — [About upcoming limits on trusted certificates (HT210176 / 398-day limit)](https://support.apple.com/en-us/103769).
- IETF RFC 5280 — [Internet X.509 Public Key Infrastructure Certificate Profile](https://datatracker.ietf.org/doc/html/rfc5280).

---

## ADR 7: Local Setup Portal, User-Agent Classifier, and Multi-Format CA Downloads

### Status
Accepted

### Context
Installing a Root CA and configuring an HTTP proxy on Fire TV, Android TV, iOS, tvOS, and custom scripts is the highest-friction step in multi-device proxying. Different devices expect different certificate encodings (`.cer`/DER vs. `.pem`) and completely different OS settings paths, and TV browsers rarely support complex client-side JavaScript or copy-paste workflows.

### Decision
- **Dual Reachability:** Serve the Setup Portal both directly on the LAN host (default `0.0.0.0:8081`, displayed on `proxided` startup with detected LAN IPv4 addresses) **and** transparently via `http://proxide.local` when proxied HTTP traffic requests that virtual host.
- **Pure Server-Rendered UI (`embed.FS`):** Bundle lightweight, zero-JS HTML + CSS templates via `//go:embed` so TV browsers (Amazon Silk on Fire TV, Android TV WebView, Safari iOS) render cleanly and reliably.
- **Pure User-Agent Classifier (`ClassifyUserAgent`):** Classify incoming `User-Agent` strings purely into `DevicePlatform` (`FireTV`, `AndroidTV`, `Android`, `iOS`, `tvOS`, `CLIController`, `Unknown`) and show tailored, step-by-step host/port + CA trust instructions (including copyable `adb` commands and controller `HTTP_PROXY`/`SSL_CERT_FILE` exports), while still linking every platform guide manually in case a browser spoofs its UA.
- **Multi-Format Read-Only CA Endpoints:** Serve `/ca.pem` (`application/x-pem-file`), `/ca.cer` & `/ca.der` (`application/pkix-cert`), `/ca.crt` (`application/x-x509-ca-cert`), and `/fingerprint` (SHA-256) strictly read-only over `GET`.

### Trade-offs & References
- **Trade-off:** Serving the portal directly on `:8081` solves the chicken-and-egg problem *before* proxy settings are entered on a TV/phone, while `http://proxide.local` provides an effortless bookmark once proxy settings are configured.
- Android Developers — [Network Security Configuration](https://developer.android.com/privacy-and-security/security-config).

---

## ADR 8: Target Device Strategy and Known Constraints

### Status
Accepted

### Context
Not all consumer streaming boxes and mobile apps treat user-installed Root CAs equally. Building fragile runtime-bypass or root-only hacks into the proxy core would complicate architecture and create misleading reliability promises.

### Decision
Classify device targets into two explicit tiers across docs, portal guides, and UX:
1. **First-Class Targets:**
   - **Fire TV & Android TV:** Explicit Wi-Fi proxy or `adb shell settings put global http_proxy <host>:<port>` helpers (integrated into `cmd/proxide adb`), plus portal `.pem`/`.cer` install guidance and explicit documentation of Android 7+ `network_security_config` behavior for release vs. debuggable/owned apps.
   - **Android Mobile:** Explicit Wi-Fi proxy + `adb` helpers + user CA installation.
   - **iOS & tvOS:** Manual Wi-Fi HTTP proxy + Safari/Apple Configurator `.cer`/`.pem` install + mandatory **Settings -> General -> About -> Certificate Trust Settings** full-trust toggle (plus Apple Configurator profile notes for tvOS).
   - **Custom Local Controllers:** Standard `HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` environment variables and optional `X-Proxide-Client` tagging.
2. **Best-Effort Targets / Known Constraints:**
   - **Roku** (lacks user-accessible global HTTP proxy UI and system user CA trust store on retail OS) and **third-party cert-pinned apps** (banking, streaming DRM, social SDKs). Proxide supports these strictly through **per-host/per-client TLS Passthrough** and `pin_suspected` surfacing rather than invasive binary patching or Frida/Xposed hooks.

### Trade-offs & References
- **Trade-off:** Accepts that retail Roku channels and third-party pinned apps bypass decryption cleanly via passthrough, keeping Proxide deterministic, zero-root, and maintainable.

---

## ADR 9: Bounded Capture Store, Non-Blocking Event Fan-Out, and Manipulation Pipeline

### Status
Accepted

### Context
Streaming TV devices regularly download multi-hundred-megabyte video chunks, firmware updates, and image assets, while an inspector UI might pause, filter, or disconnect mid-capture. Meanwhile, developers need at least one high-value manipulation capability (Map Local and/or header/body rewrite) early without corrupting HTTP framing.

### Decision
- **Dual-Bounded Capture Ring Buffer (`internal/store`):** Retain at most `DefaultRingBufferFlows = 5000` flows **and** enforce a `DefaultRingBufferMaxBytes = 256 MiB` cumulative memory ceiling, evicting oldest entries deterministically whenever either limit is reached.
- **Body Capture Cap (`1 MiB`):** Record up to `DefaultMaxBodyCaptureBytes = 1 MiB` per request/response body for inspection (`body_truncated: true` when exceeded) while continuing to stream the complete payload transparently over the wire.
- **Non-Blocking Pub/Sub Bus (`internal/bus`):** Deliver `CaptureEvent` updates to each inspector subscriber over a bounded queue (`DefaultSubscriberQueueSize = 256`). When a subscriber falls behind, drop non-blockingly and increment an exposed drop counter so live LAN device traffic never stalls.
- **Pure-Matched Manipulation Engine (`internal/rewrite`):**
  - Evaluate active `RewriteRule` snapshots (`atomic.Pointer`) matched by client IP/tag, HTTP method, host glob/regex, and URL path prefix/regex.
  - **Map Local:** Serve static local fixture files strictly within an operator-configured root directory using `os.Root` (or canonical path containment check) rejecting traversal (`ErrPathEscapesRoot`).
  - **Header & Body Rewrite:** Mutate cloned headers/bodies before upstream send (request rules) or before client write (response rules), reconciling `Content-Length`, `Transfer-Encoding`, and `Content-Encoding` cleanly and appending an `AppliedManipulation` audit entry to `CaptureEvent.Manipulations`.

### Trade-offs & References
- **Trade-off:** Capping captured bodies at `1 MiB` and keeping an in-memory ring buffer means multi-hour archival sessions require explicit JSON/HAR export in a later phase, in exchange for predictable RAM usage when proxying heavy TV/media traffic.
- IETF RFC 9110 — [HTTP Semantics (Hop-by-Hop Headers, Content-Length, Framing)](https://datatracker.ietf.org/doc/html/rfc9110).

---

## ADR 10: Layered Verification Strategy and Architecture Fitness Tests

### Status
Accepted

### Context
Concurrency bugs in Go HTTP proxies, TLS certificate edge cases across iOS/Android, path traversal in Map Local, and gradual package coupling between `cmd/proxide` and `internal/proxy` cannot be caught reliably by superficial unit tests alone.

### Decision
Enforce a four-layer verification strategy:
1. **Pure Core Unit Tests (`go test`):** Deterministic tests for `ClientRegistry` IP unmapping (`::ffff:`), `ClassifyUserAgent`, X.509 CA/leaf compliance (`<= 397d`, SANs, EKU, `-5m` clock skew, `0700`/`0600` modes), `internal/rewrite` rule evaluation & `../` path-jail guards, and bounded `internal/store`/`internal/bus` eviction/non-blocking guarantees.
2. **Native Go Fuzzing (`testing.F`):** Fuzz User-Agent parsing, SNI/host normalization, hop-by-hop header stripping, and rule glob/regex matching against malformed device inputs.
3. **Loopback End-to-End MITM TLS Integration Tests:** Run an ephemeral `proxided` pipeline on `127.0.0.1:0` against `httptest.NewTLSServer` with an ephemeral Root CA trusted by a test `http.Client`, testing HTTP forward proxy, HTTPS `CONNECT` MITM, LRU/`singleflight` concurrency, TLS passthrough, Map Local, header/body rewrites, and WS event fan-out.
4. **Mandatory Race Detector, Architecture Fitness & Static Governance:**
   - Run `go test -race ./...` as a required gate before milestone completion.
   - Run `internal/archtest` (`golang.org/x/tools/go/packages`) to assert package boundary isolation (`cmd/proxide` cannot import daemon internals; `internal/model` has zero I/O imports; zero `http.DefaultClient` / `http.DefaultServeMux` usage).
   - Enforce `gofmt`, `go vet ./...`, `.golangci.yml`, `shellcheck`/`shfmt`, and `.githooks/pre-commit`.

### Trade-offs & References
- **Trade-off:** Maintaining `internal/archtest` and loopback TLS fixtures adds small upfront test scaffolding, while preventing dependency drift and catching subtle data races before devices hit the proxy.
- Martin Fowler — [The Practical Test Pyramid](https://martinfowler.com/articles/practical-test-pyramid.html).
- Go Blog — [Introducing the Go Race Detector](https://go.dev/blog/race-detector) and [Go Fuzzing](https://go.dev/security/fuzz/).
