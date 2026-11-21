# Proxide — Master Coding Standards & Architectural Rules

This document defines the authoritative coding standards, architectural boundaries, and verification rules across **Proxide** (Go 1.27 daemon and inspector CLI, `net/http`, `crypto/tls`, `crypto/x509`, `net/netip`, `log/slog`, and Bash automation).

The architectural rationale and trade-offs behind these rules are documented in [docs/architecture-decisions.md](docs/architecture-decisions.md), Go-unique language and stdlib hazards are tracked separately in [docs/go-pitfalls.md](docs/go-pitfalls.md), and the phased implementation roadmap is tracked in [docs/01_PLAN.md](docs/01_PLAN.md).

---

## Part I: Universal Coding Standards (All Languages & Layers)

```text
+-------------------------------------------------------------------------+
|                       Universal Standards Pillars                       |
+--------------------+--------------------+-------------------------------+
| Pure Transforms    | Immutability       | Explicit Side Effects (CQS)   |
| Over Tangled Loops | by Default         | Functional Core / Imp. Shell  |
+--------------------+--------------------+-------------------------------+
| Focused Helpers    | Zero Magic Numbers | Anti-Pattern Zero Tolerance   |
+--------------------+--------------------+-------------------------------+
```

### 1. Pure, Declarative Logic Over Tangled Imperative Loops

All Go and shell code must prefer pure, single-purpose transformations over sprawling imperative loops that mix state mutation, business decisions, and network or disk I/O.

1. **Choose Pure Transformations Over Tangled Loops:**
   - **Go Adaptation:** Idiomatic Go does not wrap slices in fluent `.map().filter()` chains or fight Go's `(T, error)` return convention with monadic wrappers. Instead, isolate each transformation inside a pure function that accepts read-only inputs, executes a short, bounded `for ... range` pass or uses `slices` / `maps` stdlib helpers (`slices.Clone`, `slices.ContainsFunc`, `maps.Clone`), and returns a newly allocated value without mutating inputs or touching I/O.
   - **Bash:** Use `jq` and `awk` pipelines for structured JSON, log, and report transformations.
2. **Permitted Imperative Loop Exceptions (Must Be Commented):**
   - Long-lived or mutating loops (`for`, `for ... range`) are allowed **only** for:
     - Streaming unbuffered byte buffers or network pipes (`CONNECT` TCP tunnels, WebSocket/SSE frame pumps, `io.CopyBuffer`).
     - Accept/event loops bounded by `ctx.Done()` (`net.Listener.Accept`, event-bus fan-out workers).
     - Benchmark-proven hot paths where intermediate slice or closure allocations cause measured throughput degradation.
     - Bounded Bash retry/health probes (`wait_for_ready`) or iterating fixed `readonly` arrays in `scripts/lib.sh`.
   - **Mandatory rule:** Every streaming, retry, or hot-path loop must carry an inline comment explaining why a pure single-pass helper was rejected or how loop termination is bounded.

```go
// ❌ BAD: Tangled loop mutating input state while mixing I/O and filtering
func processFlows(flows []*CaptureEvent, clientIP string) []string {
	var hosts []string
	for _, f := range flows {
		f.Client.FriendlyName = lookupNameOnDisk(f.Client.IP) // Side effect inside transform!
		if f.Client.IP.String() == clientIP && !f.TLS.Passthrough {
			hosts = append(hosts, f.Request.Host)
		}
	}
	return hosts
}

// ✅ GOOD: Pure helper transforms immutable values with zero I/O
func FilterInterceptedHosts(flows []CaptureEvent, targetIP netip.Addr) []string {
	hosts := make([]string, 0, len(flows))
	for _, flow := range flows {
		if flow.Client.IP == targetIP && !flow.TLS.Passthrough {
			hosts = append(hosts, flow.Request.Host)
		}
	}
	return hosts
}
```

### 2. Immutability by Default

1. **Immutable Domain Contracts & Events:**
   - Once a domain value (`CaptureEvent`, `ClientIdentity`, `HTTPRequestSnapshot`, `HTTPResponseSnapshot`, `StreamFrame`, `FlowTiming`, `TLSInfo`, `AppliedManipulation`, `RewriteRule`, `ApiError`) is constructed and published across a package or concurrency boundary, it must be treated as strictly read-only.
   - Never mutate a `CaptureEvent`, `RewriteRule`, or configuration snapshot after it is stored in `internal/store` or fanned out over `internal/bus`.
2. **Defensive Cloning & Snapshot Swaps:**
   - Functions must compute new values from inputs without mutating caller-owned slices, maps, or `http.Header` structures.
   - Dynamic runtime state shared across read-heavy proxy goroutines (e.g., active `RewriteRule` lists, TLS passthrough host allowlists) must be replaced atomically via copy-on-write immutable snapshots (`atomic.Pointer[T]`) rather than mutated in place.
3. **Immutable Configuration & Artifacts:**
   - Persisted Root CA identity artifacts (`ca-cert.pem`, `ca-key.pem`) are generated once on disk and treated as immutable identity thereafter unless explicitly rotated by the operator.
   - Bash constants must be declared `readonly`.

### 3. Explicit Demarcation of Side Effects (CQS & Functional Core / Imperative Shell)

1. **Command-Query Separation (CQS):**
   - **Queries (Pure / Read-Only):** Idempotent, side-effect free, safe to retry (`Find*`, `Parse*`, `Classify*`, `Match*`, `Build*`, `Normalize*`, `Get*`, `List*`).
   - **Commands (Side-Effecting):** Explicitly mutate state, perform socket/disk I/O, sign certificates, invoke `adb`, or emit events (`Write*`, `Persist*`, `Start*`, `Apply*`, `Publish*`, `Clear*`, `Serve*`).
2. **Strict Read-Only `GET` Semantics:**
   - Every HTTP `GET` handler on both the Loopback Control API (`127.0.0.1:9090`) and the LAN Setup Portal (`0.0.0.0:8081` and `http://proxide.local`) must remain **100% read-only and idempotent** with zero state mutations.
   - Clearing flows, adding/updating rewrite rules, toggling TLS passthrough entries, and updating client aliases must use explicit `POST`, `PUT`, `PATCH`, or `DELETE` endpoints.
   - Inspecting `/ca.pem`, `/ca.cer`, `/ca.der`, or `/fingerprint` on the Setup Portal must never trigger CA creation as an accidental side effect of a portal request (CA initialization happens explicitly at daemon startup).
3. **Functional Core, Imperative Shell:**
   - Keep rewrite rule matching, User-Agent device classification, header/body transformations, X.509 leaf template construction, client IP normalization, and `ApiError` mapping 100% pure with zero disk, clock-singleton, or network dependencies.
   - Isolate TCP listeners, TLS handshakes, HTTP upstream transports, `os.Root` local file reads, CA persistence, and `adb` subprocess execution inside explicit outer shell packages (`internal/proxy`, `internal/ca`, `internal/api`, `cmd/proxided`, `cmd/proxide`).
   - Close every I/O handle (`net.Conn`, `io.ReadCloser`, `*os.File`, listeners) deterministically on exit paths.
   - In Bash scripts, label helper functions with `# Pure query: ...` or `# Side effect: ...`.

### 4. Zero Magic Numbers & String Literals

1. **Ban Unnamed Literals:** Raw HTTP status integers (`200`, `400`, `404`, `409`, `413`, `500`), port numbers (`8080`, `8081`, `9090`), buffer capacities (`5000`, `2048`), byte limits (`1048576`, `268435456`), certificate TTLs (`7d`, `397d`, `5m`), file permission bits, header keys, MIME types, and string discriminators are prohibited inside business logic.
2. **Required Replacements:**
   - Use Go stdlib `http.Status*` constants (`http.StatusOK`, `http.StatusCreated`, `http.StatusBadRequest`, `http.StatusNotFound`, `http.StatusConflict`, `http.StatusRequestEntityTooLarge`, `http.StatusInternalServerError`).
   - Centralize listener addresses, cache sizes, body capture limits, ring-buffer bounds, and timeouts as named typed constants inside `internal/config` (e.g., `DefaultProxyAddr`, `DefaultPortalAddr`, `DefaultAPIAddr`, `DefaultMaxBodyCaptureBytes`, `DefaultRingBufferFlows`, `DefaultRingBufferMaxBytes`, `DefaultCertCacheSize`, `DefaultLeafCertTTL`, `MaxAppleLeafCertTTL`).
   - Model bounded concepts with strongly typed Go `const` string/int enums (`DevicePlatform`, `FlowProtocol`, `EventKind`, `RuleAction`, `ErrorCode`) defined in `internal/model` rather than raw ad-hoc strings.
   - Declare constants as `readonly` in Bash scripts.

### 5. Eliminate Redundancy via Focused Helpers & Shared Scripts

1. **Focused Pure Helpers:** Consolidate repeated normalization, header sanitization, cert encoding, and API response writing into cohesive, single-purpose helpers rather than copy-pasting logic across handlers:
   - `internal/clientreg`: canonical `NormalizeClientIP(netip.AddrPort) netip.Addr` and tag sanitization helpers.
   - `internal/proxy`: RFC 9110 hop-by-hop header stripping and header-cloning helpers.
   - `internal/ca`: PEM/DER certificate encoding and SHA-256 fingerprint formatting helpers.
   - `internal/api`: centralized `WriteJSON` and `WriteAPIError` helpers so every endpoint emits identical envelopes and headers.
2. **Shared Shell Workflows:** Repeated build, lint, smoke-test, and `adb` proxy helper routines must live once in `scripts/lib.sh` and be `source`d — never duplicated across scripts.

---

## Part II: Go Language & Runtime Standards (Go 1.27+)

### 6. Module & Package Topology

Keep Proxide strictly layered between daemon internals, shared domain contracts, and thin inspector clients:

| Package | Role & Allowed Dependencies | Strictly Forbidden Imports |
| :--- | :--- | :--- |
| `internal/model` | Pure immutable domain types (`CaptureEvent`, `RewriteRule`, `ClientIdentity`, `ApiError`), typed enums. Stdlib value types only (`net/netip`, `time`, `net/http` header type only if pure). | `internal/proxy`, `internal/ca`, `internal/tlsmitm`, `internal/api`, `internal/store`, `internal/bus`, `os`, `net` sockets |
| `internal/config` | Typed config structs, named defaults/limits, env/flag binding, pure validation. Imports `internal/model`. | `internal/proxy`, `internal/tlsmitm`, `internal/api`, `internal/store` |
| `internal/clientreg` | IP normalization (`netip.Addr.Unmap()`), `X-Proxide-Client` extraction, friendly name registry, best-effort ARP/neighbor MAC resolver. Imports `internal/model`, `internal/config`. | `internal/proxy`, `internal/ca`, `internal/tlsmitm`, `internal/api` |
| `internal/ca` | Root CA generation/loading (`0700`/`0600` atomic write), SHA-256 fingerprint, PEM/DER encoding, leaf template builder & signer. Imports `internal/model`, `internal/config`. | `internal/proxy`, `internal/api`, `internal/portal`, `internal/store` |
| `internal/tlsmitm` | `tls.Config.GetCertificate` manager, bounded LRU cache (`2048`), `singleflight` per SNI, passthrough allowlist, cert-pin failure detector. Imports `internal/model`, `internal/config`, `internal/ca`. | `internal/api`, `internal/portal`, `internal/store`, `cmd/*` |
| `internal/rewrite` | Pure rule matcher, root-jailed Map Local responder (`os.Root`), header/body rewriter. Imports `internal/model`, `internal/config`. | `internal/ca`, `internal/tlsmitm`, `internal/api`, `internal/portal` |
| `internal/store` | Bounded ring buffer (`5000` flows / `256 MiB` byte budget), eviction, read-only query/filter views. Imports `internal/model`, `internal/config`. | `internal/proxy`, `internal/ca`, `internal/tlsmitm`, `internal/portal` |
| `internal/bus` | Non-blocking pub/sub event fan-out with bounded subscriber queues and drop counters. Imports `internal/model`, `internal/config`. | `internal/proxy`, `internal/ca`, `internal/tlsmitm`, `internal/api` |
| `internal/portal` | `embed.FS` HTML/text templates, pure User-Agent `DevicePlatform` classifier, read-only `.pem`/`.cer`/`.der`/`.crt` CA & guide handlers. Imports `internal/model`, `internal/config`, `internal/ca`. | `internal/store`, `internal/bus`, `internal/rewrite`, `internal/proxy` |
| `internal/proxy` | LAN HTTP forward proxy (RFC 9110), `CONNECT` tunnel + MITM handoff, `http://proxide.local` virtual-host routing, WS/SSE frame capture, flow timing. Imports `model`, `config`, `clientreg`, `tlsmitm`, `rewrite`, `portal`, `store`, `bus`. | `internal/api`, `cmd/*` |
| `internal/api` | Loopback-only (`127.0.0.1:9090`) REST + WebSocket/SSE server, read-only `GET` handlers, explicit rule/client/passthrough mutations, typed `ApiError`. Imports `model`, `config`, `store`, `bus`, `clientreg`, `rewrite`, `tlsmitm`, `ca`. | `internal/proxy`, `internal/portal`, `cmd/*` |
| `internal/archtest` | Automated `golang.org/x/tools/go/packages` dependency-boundary and hygiene fitness tests. | Production runtime binaries |
| `cmd/proxided` | Daemon composition root: wires config, logger, CA, registry, store, bus, rewrite, proxy, portal, loopback API, and graceful `SIGINT`/`SIGTERM` shutdown. | — |
| `cmd/proxide` | Thin inspector CLI/TUI client + `adb` proxy helper subcommands communicating **strictly** over loopback HTTP + WebSocket/SSE. Imports `internal/model` (wire contracts) + CLI client code only. | **Zero imports** of `internal/proxy`, `internal/ca`, `internal/tlsmitm`, `internal/portal`, `internal/store`, `internal/bus`, `internal/rewrite`, or `internal/api` |

**Global State Ban:**
- Package-level mutable variables, `init()` functions with side effects, `http.DefaultServeMux`, and `http.DefaultClient` are **prohibited**. Construct all dependencies explicitly in `cmd/proxided` or test harnesses and pass them via struct constructors.

### 7. Interfaces, Value Semantics & Immutability in Go

1. **Consumer-Defined Minimal Interfaces:**
   - Define narrow 1–3 method interfaces on the **consumer** side (`CertSigner`, `EventPublisher`, `ClientResolver`, `RuleEvaluator`), following Go's "accept interfaces, return concrete structs" rule.
   - Never create bloated "kitchen-sink" interfaces just to mock concrete types.
2. **Ownership & Cloning Rules:**
   - Constructors and boundary publishers must defensively clone caller-supplied slices, maps, and `http.Header` instances (`slices.Clone`, `maps.Clone`, `http.Header.Clone()`) so later modifications cannot race with stored or broadcast events.
   - Prefer passing small immutable value structs (`ClientIdentity`, `FlowTiming`, `TLSInfo`) by value.
3. **Lock-Free Read-Mostly Snapshots:**
   - Store active rule sets and passthrough allowlists inside `atomic.Pointer[Snapshot]` so hot proxy request paths read without acquiring mutex locks, while control API updates build and swap a new immutable snapshot.

### 8. Explicit Error Handling & Wrapping

1. **Handle Every Error:** Never discard returned errors with `_ = ...` unless documented with a brief inline comment on best-effort cleanup (e.g., closing a response body after a write failure).
2. **Wrap for Callers:** Wrap errors with concise contextual verbs and `%w` (`fmt.Errorf("sign leaf cert for %q: %w", host, err)`) so callers can match via `errors.Is` and `errors.As`.
3. **Sentinel & Domain Errors:** Define clear sentinel errors in `internal/model` or owning core packages (`ErrCertPinned`, `ErrRuleConflict`, `ErrPathEscapesRoot`, `ErrFlowNotFound`, `ErrInvalidConfig`) and map them cleanly to `ApiError` at the `internal/api` boundary.
4. **No Panics in Request/Connection Paths:** Never call `panic` on malformed client headers, broken TLS handshakes, invalid JSON, or missing rules. Wrap per-connection proxy goroutines and HTTP handlers with panic recovery that logs stack details safely via `slog` and closes the affected connection so a single malformed device packet never takes down `proxided`.

### 9. Context Propagation, Goroutine Lifecycle & Bounded Resources

1. **`context.Context` Discipline:**
   - Pass `ctx context.Context` as the first parameter of every blocking, network, disk, or lifecycle function.
   - **Never** store a `context.Context` inside a struct field.
   - Derive per-request or per-handshake timeouts via `context.WithTimeout` rather than relying on global server write timeouts that would terminate long-lived `CONNECT` or WebSocket streams.
2. **Goroutine Ownership & Shutdown:**
   - Every goroutine spawned in Proxide must have a single clear owner, respond to `ctx.Done()`, and drain cleanly on shutdown via `sync.WaitGroup` or `errgroup.Group`.
   - `cmd/proxided` must execute an ordered graceful shutdown on `SIGINT`/`SIGTERM`: stop accepting new proxy/portal/API connections, drain active control streams, flush subscriber closes on `internal/bus`, and close open handles within a bounded shutdown deadline.
3. **Hard Resource Bounds:**
   - Every reader, queue, cache, and memory buffer must enforce explicit bounds:
     - Capture bodies capped at `DefaultMaxBodyCaptureBytes` (`1 MiB`); proxy streams continue passing bytes upstream/downstream without buffering unbounded payloads into RAM.
     - Control API JSON request bodies wrapped with `http.MaxBytesReader`.
     - In-memory flow ring buffer bounded by **both** item count (`DefaultRingBufferFlows = 5000`) and cumulative byte budget (`DefaultRingBufferMaxBytes = 256 MiB`).
     - Leaf certificate cache bounded via LRU (`DefaultCertCacheSize = 2048`).
     - `internal/bus` subscriber channels bounded (e.g., `DefaultSubscriberQueueSize = 256`) with non-blocking drop policy.

### 10. Structured Logging (`log/slog`) & Secret Hygiene

1. **Injected `*slog.Logger`:** Pass `*slog.Logger` explicitly at startup; avoid global `slog.Default()` mutation inside library packages. Never use `fmt.Println` or stdlib `log.Printf` in daemon internals (`internal/*` or `cmd/proxided`).
2. **Standard Structured Keys:** Use uniform snake_case keys across all logs: `flow_id`, `client_ip`, `client_tag`, `device_platform`, `host`, `method`, `status`, `protocol`, `duration_ms`, `passthrough`, `err`.
3. **Secret & Key Hygiene:**
   - Never log Root CA private key material (`ca-key.pem`), raw TLS session keys, or full unredacted credentials.
   - Provide an explicit redaction helper for sensitive headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`) when exporting captures or emitting diagnostic logs outside explicit debug inspection.

---

## Part III: Proxide Engine, TLS MITM & Local API Standards

### 11. Daemon / Inspector Split & Wire Event Contract

1. **Process & Responsibility Split:**
   - `proxided` owns all LAN sockets, CA material, dynamic leaf signing, capture storage, manipulation execution, and the loopback Control API.
   - Inspector clients (`cmd/proxide` TUI/CLI, future web or desktop UIs) are stateless or presentation-only consumers of `127.0.0.1:9090` REST + WebSocket/SSE endpoints. Swapping or adding an inspector UI must require **zero** edits to `internal/proxy`, `internal/ca`, or `internal/tlsmitm`.
2. **Structured `CaptureEvent` Contract:**
   - Every captured flow emits immutable snapshots containing: `id`, `client` (`ip`, `tag`, `friendly_name`, `mac`, `platform`), `protocol` (`http`, `https`, `ws`, `wss`, `sse`, `tunnel`), `request`, `response`, `stream_frames` (for WebSocket/SSE frames), `timing` (DNS, TCP connect, TLS handshake, TTFB, total duration), `tls` (SNI, ALPN, cipher, leaf cert serial, `passthrough`, `pin_suspected`), and `manipulations` (`AppliedManipulation` rule IDs and action kinds).
3. **Loopback Control API (`127.0.0.1:9090`):**
   - Bind strictly to loopback (`127.0.0.1:9090`) by default. Any explicit non-loopback override (`--api-listen`) must require explicit opt-in and authentication configuration.
   - Map all API errors to a typed JSON `ApiError` (`code`, `message`, `trace_id`, optional `field_errors`). Outside explicit `--debug` mode, `500 Internal Server Error` responses must never leak filesystem paths, OS details, or stack traces.
4. **Non-Blocking Event Fan-Out:**
   - `internal/bus` must publish `CaptureEvent` notifications non-blockingly (`select { case sub <- evt: default: ... }`), dropping the oldest or excess queued event and incrementing an atomic dropped counter rather than stalling `internal/proxy` handlers when an inspector disconnects or lags.

### 12. LAN Proxy, `CONNECT` Tunneling & Client Tagging

1. **LAN Binding & Interface Selection:**
   - Bind the proxy listener to `0.0.0.0:8080` by default or to a specific LAN interface/IP via `--listen` / `--iface`.
2. **HTTP Forward Proxy Fidelity:**
   - Strip RFC 9110 hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`, plus any header names listed in `Connection`) before forwarding HTTP requests and responses.
   - Execute upstream HTTP calls using `http.Transport.RoundTrip` directly (never `http.Client.Do`, which silently chases redirects) with `DisableCompression: true` so encoded responses reach target devices intact unless explicitly rewritten.
3. **`CONNECT` Tunneling & Half-Close:**
   - For passthrough hosts or raw non-MITM tunnels, send `HTTP/1.1 200 Connection Established\r\n\r\n`, hijack the underlying `net.Conn`, and pump bytes bidirectionally with proper half-close (`CloseWrite`) propagation and cancellation.
4. **Client Identity & Tagging (`internal/clientreg`):**
   - Normalize every peer `netip.AddrPort` with `.Addr().Unmap()` so IPv4-mapped IPv6 addresses (`::ffff:192.168.1.42`) never fragment client tracking.
   - Extract optional custom client tags from `X-Proxide-Client` (configurable header name); strip the internal tag header before forwarding upstream by default unless configured to preserve.
   - Resolve friendly aliases (operator-assigned names) and best-effort MAC addresses from OS neighbor/ARP tables without requiring root privileges or raw packet capture.
5. **Target Device Assumptions:**
   - **First-class targets:** Fire TV, Android TV, Android mobile (Wi-Fi proxy + `adb shell settings put global http_proxy` helpers; document Android 7+ user-CA restriction for release APKs without `network_security_config`), iOS, tvOS (Wi-Fi manual proxy + `.cer`/`.pem` install + Settings -> Certificate Trust Settings), and custom local controllers (`HTTP_PROXY`, `HTTPS_PROXY`, `SSL_CERT_FILE`, `X-Proxide-Client`).
   - **Best-effort targets:** Roku and certificate-pinned mobile/TV apps are treated explicitly as known constraints supported via per-host/per-client **TLS Passthrough allowlists** and automatic pin-failure detection rather than invasive runtime hooking.

### 13. Local Root CA, Dynamic SNI MITM & Setup Portal

1. **Root CA Lifecycle (`internal/ca`):**
   - Generate the Root CA once on disk inside a `0700` state directory, writing `ca-key.pem` with mode `0600` via temp file + atomic `os.Rename`, and `ca-cert.pem` with mode `0644`. Never overwrite an existing valid CA silently.
   - Default to **ECDSA P-256** (`elliptic.P256()`) for sub-millisecond leaf signing and broad compatibility across iOS 13+, tvOS, Android 7+, FireOS, and Go/OpenSSL controllers; allow an explicit RSA-2048 fallback config for legacy clients.
2. **Dynamic SNI Leaf Certificates (`internal/tlsmitm`):**
   - Sign leaf certificates on demand inside `tls.Config.GetCertificate` using the TLS `ClientHelloInfo.ServerName` (falling back to `CONNECT` target host/IP if SNI is empty).
   - Every generated leaf certificate must satisfy strict mobile/TV trust rules:
     - `NotBefore` backdated by **5 minutes** (`LeafClockSkewBackdate = 5 * time.Minute`) to tolerate device clock drift.
     - Validity duration default **7 days** (`DefaultLeafCertTTL = 7 * 24 * time.Hour`), strictly bounded `<= 397 days` (`MaxAppleLeafCertTTL = 397 * 24 * time.Hour`) for Apple iOS/tvOS compliance.
     - Mandatory Subject Alternative Names (`DNSNames` for hostnames, `IPAddresses` for IP literals — never rely solely on `CommonName`).
     - `KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment` (for RSA) and `ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}`.
     - Cryptographically random positive 128-bit serial numbers via `crypto/rand` on every leaf certificate.
   - Cache signed `*tls.Certificate` objects in a bounded in-memory LRU (`DefaultCertCacheSize = 2048`) keyed by normalized hostname, wrapped with `golang.org/x/sync/singleflight` so concurrent device connections to the same CDN host sign at most once without holding a global mutex during key generation/signing.
3. **Upstream TLS Verification & Passthrough:**
   - Upstream connections verify certificates against system roots (`InsecureSkipVerify: false`) by default; allow insecure upstream bypass only via explicit per-host/dev flags.
   - Track consecutive client-side TLS alert / EOF-immediately-after-ServerHello events per `(client, host)` to flag `pin_suspected = true` and suggest adding the host to the passthrough allowlist.
4. **Local Setup Portal (`internal/portal`):**
   - Embed HTML/CSS/guide templates via `//go:embed` (`embed.FS`).
   - Serve the Setup Portal both directly on the LAN host (`0.0.0.0:8081`) and transparently when proxied requests target `http://proxide.local`.
   - Classify devices from `User-Agent` using a pure classifier (`ClassifyUserAgent(ua string) DevicePlatform`) covering `FireTV`, `AndroidTV`, `Android`, `iOS`, `tvOS`, `CLIController`, and `Unknown`.
   - Expose read-only CA download endpoints (`/ca.pem`, `/ca.cer`, `/ca.der`, `/ca.crt`, `/fingerprint`) with proper MIME types (`application/x-pem-file`, `application/pkix-cert`, `application/x-x509-ca-cert`) and zero private-key exposure.

### 14. Manipulation Pipeline (Map Local & Header/Body Rewrite)

1. **Pure Rule Evaluation (`internal/rewrite`):**
   - Match rules deterministically by priority/order using pure predicates over client IP/tag, HTTP method, host glob/regex, and URL path prefix/regex.
2. **Root-Jailed Map Local:**
   - Map Local rules must serve files strictly beneath an operator-configured root directory using Go's `os.Root` (or verified canonical containment checks) to guarantee zero `../` or symlink path-traversal escapes (`ErrPathEscapesRoot`).
3. **Header & Body Rewrites:**
   - When modifying request or response bodies, reconcile `Content-Length` accurately, remove conflicting `Transfer-Encoding` headers, and respect or strip `Content-Encoding` explicitly so target devices never stall or fail decompression.
   - Record every applied manipulation (`rule_id`, `rule_name`, `action`, `target`) onto `CaptureEvent.Manipulations` so the inspector clearly distinguishes original traffic from rewritten responses.

---

## Part IV: Testing, Architecture Fitness, Bash & Pre-Commit Governance

### 15. Test Pyramid & Go Verification Gates

Follow [The Practical Test Pyramid](https://martinfowler.com/articles/practical-test-pyramid.html):

1. **Fast Pure Unit Tests (`go test`):**
   - Test `internal/model`, `internal/config`, `internal/clientreg` (IP unmapping & tag parsing), `internal/portal` (pure `ClassifyUserAgent` matrix across Fire TV, Android TV, Android, iOS, tvOS, curl/Go/Python), `internal/ca` (SANs, serial uniqueness, `<= 397d` validity, PEM/DER round-trip), and `internal/rewrite` (rule matching & path-jail traversal rejection) in milliseconds with zero network sockets.
2. **Go Native Fuzz Tests (`Fuzz*`):**
   - Maintain fuzz targets (`testing.F`) for User-Agent classification, SNI/host normalization, HTTP header parsing/hop-by-hop stripping, and rewrite pattern matching against malformed device traffic.
3. **Loopback End-to-End MITM Integration Tests:**
   - Spin up ephemeral Root CA + `proxided` components on `127.0.0.1:0` + `httptest.NewTLSServer` upstream + Go `http.Client` trusting the ephemeral Root CA to test HTTP forward proxying, HTTPS `CONNECT` MITM, dynamic SNI leaf caching, passthrough bypass, Map Local, header/body rewrite, and WebSocket event fan-out end to end without external internet access.
4. **Mandatory Race Detector Gate:**
   - Run `go test -race ./...` across all packages before any milestone or PR completes. Zero data races allowed.
5. **Architecture Fitness Tests (`internal/archtest`):**
   - Use `golang.org/x/tools/go/packages` (Go's counterpart to Portfolio's Konsist tests) to automatically fail the build if:
     - `cmd/proxide` imports `internal/proxy`, `internal/ca`, `internal/tlsmitm`, `internal/portal`, `internal/store`, `internal/bus`, `internal/rewrite`, or `internal/api`.
     - `internal/model` imports any I/O, socket, or internal daemon engine package.
     - `internal/portal`, `internal/rewrite`, or `internal/clientreg` imports `internal/proxy` or `internal/api`.
     - Any package inside `internal/` imports `http.DefaultClient` or registers routes on `http.DefaultServeMux`.

### 16. Linting, Formatting, Bash Scripts & `.githooks/pre-commit`

- **Go Formatting & Static Analysis:**
  - `gofmt` (and `goimports`) across all `.go` files.
  - `go vet ./...` mandatory zero warnings.
  - `.golangci.yml` enforcing `errcheck`, `bodyclose`, `noctx`, `nilerr`, `copylocks`, `exhaustive`, `gosec`, `gocritic`, `revive`, and `depguard` (blocking `http.DefaultClient`, `http.DefaultServeMux`, and disallowed internal imports).
- **Editor Hygiene (`.editorconfig`):**
  - Tabs (`indent_style = tab`) for `.go` files (matching `gofmt`), 4-space indentation for `.sh`, `.yml`, `.yaml`, UTF-8, LF line endings, trimmed trailing whitespace, and final newline.
- **Bash Standards (`scripts/`):**
  - Begin executable scripts with `#!/usr/bin/env bash` and `set -euo pipefail`.
  - `source` shared helpers from `scripts/lib.sh` (`# shellcheck source=lib.sh`), validate inputs up front, verify prerequisites via `require_command`, quote all expansions (`"${var}"`), declare locals inside functions, mark constants `readonly`, format with `shfmt -i 4`, and verify with `shellcheck`.
- **Pre-Commit Hook (`.githooks/pre-commit`):**
  - Automatically checks/formats staged `.go` and `.sh` files, executes `go vet ./...`, checks `bash -n`, and runs fast pure + architecture fitness unit tests before allowing commits.

---

## Part V: Universal Anti-Pattern & Remedy Catalog

> **Scope Note:** This table lists strictly **language-agnostic** engineering and proxy-architecture anti-patterns. Go-specific compiler, runtime, concurrency, and stdlib pitfalls are maintained separately in [Part VI](#part-vi-go-specific-pitfalls-tracked-separately) and [docs/go-pitfalls.md](docs/go-pitfalls.md).

| Anti-Pattern | Risk | Required Remedy |
| :--- | :--- | :--- |
| Coupling inspector UI/CLI directly to proxy or TLS code | Tight coupling makes swapping TUI/web/desktop views brittle and risks exposing CA/sockets in UI layers | Isolate `proxided` engine behind the loopback REST + WS/SSE `CaptureEvent` API (`cmd/proxide` imports wire models only) |
| Exposing Control API or CA private key on LAN `0.0.0.0` | Any LAN device could clear captures, inject rewrite rules, or forge trusted certificates | Bind Control API strictly to `127.0.0.1:9090`; keep `ca-key.pem` `0600` on disk and serve public certs only on the Setup Portal |
| Mutating state inside HTTP `GET` endpoints | Violates HTTP idempotency; accidental browser prefetch or crawler hits alter rules/flows/CA state | Keep all `GET` routes 100% read-only; require `POST`/`PUT`/`PATCH`/`DELETE` for mutations and initialize CA on startup |
| Unbounded body capture or unbounded in-memory flow history | Large video/OTA downloads on Fire TV/Apple TV trigger immediate OOM crashes | Cap captured bodies at `1 MiB` while streaming full payloads; bound store by count (`5000`) and byte budget (`256 MiB`) |
| Synchronous or blocking telemetry fan-out to slow UIs | A stalled or paused TUI/web inspector freezes live LAN proxy connections across all devices | Use non-blocking per-subscriber bounded queues with drop-oldest / drop-counter backpressure |
| Raw unnamed literals for ports, limits, TTLs, or enums | Silent divergence between portal guides, CA policy checks, and API bounds | Centralize all constants in `internal/config` and typed enums in `internal/model`; use `http.Status*` constants |
| Trusting client-supplied file paths in Map Local rules | Directory traversal (`../../etc/passwd`) leaks host filesystem files to LAN devices | Enforce root-jailed file resolution (`os.Root` / canonical prefix check) rejecting escaping paths (`ErrPathEscapesRoot`) |
| Mixing I/O side effects inside pure matchers or classifiers | Impossible to fuzz or unit-test cleanly without live sockets or filesystem state | Keep `internal/rewrite` matchers, UA classification, IP normalization, and cert templates pure with zero I/O |
| Assuming Roku or cert-pinned apps support transparent MITM | Causes broken apps, infinite retry storms, and wasted debugging effort | Support per-host/per-client TLS Passthrough allowlists and surface `pin_suspected` diagnostics explicitly |
| Logging CA private keys, auth headers, or raw internal stack traces in `500` responses | Credential compromise and internal path disclosure | Never log private keys; redact sensitive headers on export; sanitize `500` `ApiError` responses with `trace_id` outside debug mode |

---

## Part VI: Go-Specific Pitfalls (Tracked Separately)

All pitfalls that are unique to **Go's type system, memory model, `defer`/error semantics, goroutine scheduler, `net/http` proxy plumbing, `crypto/tls`/`crypto/x509` internals, and `encoding/json`** are tracked separately in **[docs/go-pitfalls.md](docs/go-pitfalls.md)**. Separating Go-unique footguns from universal engineering rules keeps Part I–Part V portable across languages while giving contributors (especially those moving from Kotlin/JVM or Rust) a fast, high-signal Go checklist.

| Category | Key Go-Unique Traps Covered | Authoritative Reference |
| :--- | :--- | :--- |
| **1. Type System, Interfaces & Aliasing** | Typed `nil` interfaces, slice backing-array aliasing, fatal concurrent map panics, `nil` map writes vs `nil` slice JSON, `sync` primitive copies, interface wrapping hiding `Hijacker`/`Flusher` | [docs/go-pitfalls.md §1](docs/go-pitfalls.md#1-type-system-interfaces--memory-aliasing) |
| **2. Control Flow, `defer` & Errors** | Function-scoped `defer` in loops, immediate `defer` arg evaluation, `:=` `err` shadowing, `==` vs `errors.Is`/`errors.As`, per-goroutine `recover()` scope | [docs/go-pitfalls.md §2](docs/go-pitfalls.md#2-control-flow-defer--error-handling) |
| **3. Goroutines, Channels & Timers** | Blocked channel leaks, sender-only close panics, `time.After` timer churn in hot loops, `wg.Add(1)` inside goroutines, shared read-buffer races | [docs/go-pitfalls.md §3](docs/go-pitfalls.md#3-goroutines-channels--timers) |
| **4. `net/http`, `net.Conn` & Proxying** | `WriteTimeout` killing `CONNECT`/SSE streams, unclosed `resp.Body`, `Unwrap()` for `ResponseController`, restoring `req.Body`, `Content-Length` drift, `DisableCompression`, `RoundTrip` vs `Do`, canonical headers/`req.Host`, half-close leaks, `::ffff:` IPv4-mapped IPv6 unmapping | [docs/go-pitfalls.md §4](docs/go-pitfalls.md#4-nethttp-netconn--proxying-footguns) |
| **5. `crypto/tls` & `crypto/x509` MITM** | Lock contention & thundering herd in `GetCertificate`, Apple `<= 397d` & SAN/EKU/clock-skew rules, serial collisions, ALPN `h2` vs HTTP/1.1 mismatch, non-atomic `0644` CA key writes | [docs/go-pitfalls.md §5](docs/go-pitfalls.md#5-cryptotls--cryptox509-mitm-footguns) |
| **6. `encoding/json` & I/O Decoding** | `any` numeric `float64` precision loss, `[]byte` base64 marshaling, silent unknown fields, unbounded `io.ReadAll` OOMs, trailing JSON tokens | [docs/go-pitfalls.md §6](docs/go-pitfalls.md#6-encodingjson--io-decoding-footguns) |
