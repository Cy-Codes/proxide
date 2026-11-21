# Proxide — Go-Specific Pitfalls & Remedies Catalog

> **Maintenance Rule:** Keep this registry strictly focused on **Go-unique language, runtime, stdlib, and concurrency hazards** (universal engineering rules live in [CODING_STANDARDS.md](../CODING_STANDARDS.md)). Whenever code review, fuzzing, or incident debugging uncovers a new Go-specific footgun in Proxide, append an entry (`GP-<n>`) and update the [Quick-Reference Detection Matrix](#quick-reference-detection-matrix).
>
> This guide is written specifically for engineers moving from **Kotlin/JVM or Rust** into a concurrent Go (`go1.27+`) MITM HTTP/HTTPS proxy daemon.

---

## 1. Type System, Interfaces & Memory Aliasing

### GP-01: Typed `nil` Inside an Interface Fails `err == nil`

- **Why it hits Go / Proxide:** A Go interface value holds two words: `(type, value)`. Returning a typed `nil` pointer (`var e *ApiError = nil`) as `error` produces a **non-nil** interface `(*ApiError, nil)` because the type descriptor is populated. Callers checking `if err != nil` treat success as failure.
- **Automated Catch:** `golangci-lint` (`nilness`, `govet`), unit tests.

```go
// ❌ BAD: Returns a non-nil error interface wrapping a nil *ApiError pointer
func validateRule(r RewriteRule) error {
	var apiErr *ApiError
	if r.ID == "" {
		apiErr = &ApiError{Code: CodeValidation}
	}
	return apiErr // BUG: (apiErr != nil) is TRUE for valid rules!
}

// ✅ GOOD: Return explicit untyped nil on the success path
func validateRule(r RewriteRule) error {
	if r.ID == "" {
		return &ApiError{Code: CodeValidation}
	}
	return nil
}
```

### GP-02: Slice Sub-Slicing & `append` Mutate Shared Backing Arrays

- **Why it hits Go / Proxide:** Sub-slicing `b[:n]` preserves remaining capacity (`cap(b)`). If `internal/proxy` passes captured header/body slices to `internal/bus` or `internal/store` without clamping capacity, a later `append` overwrites bytes belonging to another flow or races across goroutines.
- **Automated Catch:** `go test -race ./...`.

```go
// ❌ BAD: Caller retains shared tail capacity; later append corrupts stored frame
func snapshotPrefix(buf []byte, n int) []byte {
	return buf[:n]
}

// ✅ GOOD: Clone at ownership boundaries (or cap with 3-index slice buf[:n:n] for read-only views)
func snapshotPrefix(buf []byte, n int) []byte {
	return slices.Clone(buf[:n])
}
```

### GP-03: Concurrent Map Read/Write Triggers an Unrecoverable Fatal Panic

- **Why it hits Go / Proxide:** Unlike Java `ConcurrentHashMap` or Rust compile-time `Send`/`Sync` borrow checks, Go's built-in `map` crashes the entire `proxided` process with `fatal error: concurrent map read and map write` — which **cannot be caught by `recover()`**. High-risk spots are `ClientRegistry`, leaf certificate caches, and header/rule lookups.
- **Automated Catch:** `go test -race ./...`.
- **Required Fix:** Protect mutable maps with `sync.RWMutex`, shard locks, or swap immutable map snapshots via `atomic.Pointer`.

### GP-04: Writing to a `nil` Map Panics vs. `nil` Slice Marshaling as JSON `null`

- **Why it hits Go / Proxide:** Reading a `nil` map returns the zero value safely, whereas writing `m[k] = v` to a `nil` map panics at runtime. Conversely, an uninitialized `var frames []StreamFrame` serializes to JSON `"stream_frames": null` instead of `[]`, breaking strict inspector UI clients.
- **Automated Catch:** Unit tests asserting JSON contracts; `nil` map checks in review.
- **Required Fix:** Always initialize maps with `make(map[K]V)` before insertion and initialize public API/event slices as non-nil empty slices (`make([]T, 0)` or `[]T{}`) when serialized to JSON.

### GP-05: Copying `sync` Primitives (`sync.Mutex`, `WaitGroup`, `Once`, `atomic.Value`) by Value

- **Why it hits Go / Proxide:** Passing a struct containing a `sync.Mutex` or `sync.WaitGroup` by value copies its internal lock state, causing silent unlocked writes, deadlocks, or corrupted reference counts.
- **Automated Catch:** `go vet ./...` (`copylocks`), `golangci-lint` (`govet`).
- **Required Fix:** Always pass synchronization-owning structs by pointer (`*ClientRegistry`, `*CertCache`, `*RingStore`), never by value.

### GP-06: String Indexing Yields Raw Bytes, Not Unicode Runes

- **Why it hits Go / Proxide:** In Go, `s[i]` returns a `byte` and `len(s)` returns byte length, unlike Kotlin `Char` or Rust explicit `.bytes()` vs `.chars()`. Truncating friendly device names or URL paths at byte offsets splits multi-byte UTF-8 characters mid-sequence, producing invalid UTF-8 in JSON/TUI output.
- **Automated Catch:** Fuzz tests (`Fuzz*`), unit tests with non-ASCII device names (e.g., `"Living Room TV — 📺"`).
- **Required Fix:** Use `utf8.RuneCountInString`, `for _, r := range s`, or rune-boundary truncation helpers before slicing display strings.

### GP-07: Struct Embedding & Wrapper Types Accidentally Hide or Expose Optional Interfaces

- **Why it hits Go / Proxide:** Go's `net/http` relies on optional interface assertions (`http.Hijacker`, `http.Flusher`, `io.ReaderFrom`, `CloseWrite`). Wrapping `http.ResponseWriter` in a logging/timing struct hides `http.Hijacker` and breaks `CONNECT` tunneling; conversely, embedding a `net.Conn` can leak uninstrumented `ReadFrom`/`WriteTo` fast paths that bypass byte counters.
- **Automated Catch:** Loopback integration tests (`CONNECT` + WS/SSE + byte-count verification).
- **Required Fix:** Implement `Unwrap() http.ResponseWriter` on response wrappers (used automatically by `http.NewResponseController`), and wrap `net.Conn` explicitly without blind struct embedding when intercepting bytes.

---

## 2. Control Flow, `defer` & Error Handling

### GP-08: `defer` Is Function-Scoped, Not Block-Scoped

- **Why it hits Go / Proxide:** Unlike C++ RAII or Rust `Drop` at scope exit, `defer` runs when the **enclosing function** returns. Calling `defer resp.Body.Close()` or `defer conn.Close()` inside a proxy retry loop or streaming handler leaks file descriptors and sockets until the connection closes.
- **Automated Catch:** `golangci-lint` (`gocritic` `deferInLoop`, `revive` `defer`).

```go
// ❌ BAD: Defers accumulate across every loop iteration until the function exits
for _, target := range targets {
	resp, err := transport.RoundTrip(reqFor(target))
	if err != nil {
		continue
	}
	defer resp.Body.Close() // BUG: Holds every response socket open until function return!
}

// ✅ GOOD: Extract each iteration into a small helper so defer runs at each attempt exit
for _, target := range targets {
	if err := forwardOnce(ctx, transport, reqFor(target)); err == nil {
		break
	}
}
```

### GP-09: `defer` Evaluates Arguments Immediately at Registration Time

- **Why it hits Go / Proxide:** `defer logDuration(time.Since(start))` evaluates `time.Since(start)` immediately (~`0ns`) when the `defer` statement executes, not when the function returns. The same applies to `defer recordStatus(status)` if `status` is reassigned later.
- **Automated Catch:** `golangci-lint` (`govet` / review), unit tests checking non-zero `FlowTiming`.

```go
// ❌ BAD: time.Since(start) is frozen when defer is registered (~0ms!)
start := time.Now()
defer emitFlow(start, time.Since(start))

// ✅ GOOD: Wrap dynamic expressions in a closure evaluated at function exit
start := time.Now()
defer func() {
	emitFlow(start, time.Since(start))
}()
```

### GP-10: Short Variable Declaration `:=` Shadowing `err` or `ctx`

- **Why it hits Go / Proxide:** Inside an `if` or `switch` block, `val, err := doWork(ctx)` declares a **new inner `err`** (or inner `ctx`) whenever at least one variable on the LHS is new in that inner scope, silently leaving the outer `err` as `nil` or masking a timeout context.
- **Automated Catch:** `go vet -shadow` / `golangci-lint` (`govet` with `shadow: true`).
- **Required Fix:** Pre-declare `err` or assign with `=` inside inner blocks, and verify errors immediately before leaving the scope.

### GP-11: Comparing Wrapped Errors with `==` Instead of `errors.Is` / `errors.As`

- **Why it hits Go / Proxide:** `fmt.Errorf("...: %w", err)` wraps sentinel errors (`ErrCertPinned`, `ErrPathEscapesRoot`) and `*net.OpError`. Comparing `err == ErrPathEscapesRoot` or type-asserting `err.(*x509.UnknownAuthorityError)` fails once any layer wraps the error.
- **Automated Catch:** `golangci-lint` (`errorlint`).
- **Required Fix:** Always inspect errors using `errors.Is(err, target)` and `errors.As(err, &typed)`.

### GP-12: `recover()` Only Protects the Current Goroutine

- **Why it hits Go / Proxide:** Every accepted LAN proxy connection and WebSocket/SSE pump runs in its own goroutine. A panic inside any spawned goroutine (even if `main` has a top-level `recover()`) immediately terminates the entire `proxided` daemon process.
- **Automated Catch:** Code review, fuzz tests, connection-fault integration tests.
- **Required Fix:** Wrap every newly spawned goroutine entrypoint (`go func() { ... }()`) with a focused `defer recoverPanic(logger)` boundary helper that logs the panic + stack trace and closes only the failing connection/worker.

---

## 3. Goroutines, Channels & Timers

### GP-13: Goroutine Leaks on Blocked Channel Sends/Receives

- **Why it hits Go / Proxide:** Sending a `CaptureEvent` to an unbuffered or full subscriber channel blocks the proxy request goroutine forever if an inspector client hangs or disconnects without draining.
- **Automated Catch:** `go test -race` + goroutine leak checks (`goleak` or runtime count assertions).

```go
// ❌ BAD: Slow inspector stalls live LAN proxy traffic forever
func (b *Bus) Publish(evt model.CaptureEvent) {
	for _, ch := range b.subsSnapshot() {
		ch <- evt // Blocks entire proxy flow if subscriber stalls!
	}
}

// ✅ GOOD: Non-blocking publish drops excess/oldest event and tracks dropped metrics
func (b *Bus) Publish(evt model.CaptureEvent) {
	for _, sub := range b.subsSnapshot() {
		select {
		case sub.ch <- evt:
		default:
			sub.dropped.Add(1)
		}
	}
}
```

### GP-14: Closing a Channel Twice or Sending on a Closed Channel Panics

- **Why it hits Go / Proxide:** Only the **sender** owns channel closing. If a consumer cancels an inspector subscription and closes its own channel while `internal/bus` attempts to send an event, `proxided` panics (`send on closed channel`).
- **Automated Catch:** `go test -race ./...`.
- **Required Fix:** Have the producer/bus own and close subscriber channels exclusively on unsubscribe/shutdown, or track lifecycle via a `done` channel / `sync.Once` + `select` over `ctx.Done()`.

### GP-15: `time.After` Inside Hot `select` Loops Causes Timer Churn

- **Why it hits Go / Proxide:** Calling `time.After(d)` inside a tight loop allocates a new runtime timer on every single message/frame iteration; even when garbage-collected faster in modern Go, it creates measurable allocation pressure on high-rate WebSocket/SSE streams.
- **Automated Catch:** Benchmarks (`go test -bench . -benchmem`), `golangci-lint` (`gocritic`).
- **Required Fix:** Allocate one `timer := time.NewTimer(timeout)` outside the loop, `defer timer.Stop()`, and `timer.Reset(timeout)` cleanly on each iteration.

### GP-16: Calling `wg.Add(1)` Inside the Spawned Goroutine

- **Why it hits Go / Proxide:** Calling `wg.Add(1)` inside `go func()` races with `wg.Wait()`, allowing `Wait()` to return while workers have not yet registered or panicking (`WaitGroup is reused before previous Wait has returned`).
- **Automated Catch:** `go test -race ./...`, `golangci-lint` (`govet`).
- **Required Fix:** Always call `wg.Add(1)` synchronously **before** launching `go func()`.

### GP-17: Reusing a Shared Byte Buffer Across Goroutines in a Read Loop

- **Why it hits Go / Proxide:** Go 1.22 fixed loop-variable capture (`for i := range ...`), so loop variables no longer alias by default — **however**, reusing a single `buf := make([]byte, chunkSize)` across iterations and passing `buf[:n]` to another goroutine (`internal/bus` or async capture) still races!
- **Automated Catch:** `go test -race ./...`.
- **Required Fix:** Always copy (`slices.Clone(buf[:n])`) before handing read bytes to any asynchronous consumer or ring buffer.

---

## 4. `net/http`, `net.Conn` & Proxying Footguns

### GP-18: Zero Server Timeouts vs. `http.Server.WriteTimeout` Killing `CONNECT`/SSE Streams

- **Why it hits Go / Proxide:** A bare `&http.Server{}` has zero timeouts (vulnerable to Slowloris from misbehaving LAN devices), yet setting `WriteTimeout: 30 * time.Second` on the proxy server kills long-lived HTTPS `CONNECT` tunnels and SSE/WebSocket streams after 30 seconds!
- **Automated Catch:** Long-lived `CONNECT` and SSE integration tests.
- **Required Fix:** Set `ReadHeaderTimeout` and `IdleTimeout` on `http.Server` (leaving global `WriteTimeout = 0` on tunnel/streaming listeners), enforce per-request upstream timeouts via `ctx`, and apply per-write deadlines via `http.NewResponseController(w).SetWriteDeadline(...)` on ordinary buffered responses.

### GP-19: Failing to Drain and Close `resp.Body` Breaks Keep-Alive Pooling

- **Why it hits Go / Proxide:** `http.Transport` cannot reuse a persistent upstream TCP/TLS connection unless `resp.Body` is **both** read to `io.EOF` (boundedly) and closed. Leaving unread bytes or forgetting `resp.Body.Close()` leaks sockets and forces fresh TLS handshakes on every API call.
- **Automated Catch:** `golangci-lint` (`bodyclose`), transport socket-reuse tests.
- **Required Fix:** Always `defer resp.Body.Close()`, and on error/discard paths drain a small bounded tail (`io.CopyN(io.Discard, resp.Body, maxDrainBytes)`) before closing.

### GP-20: Wrapping `http.ResponseWriter` Breaks `http.Hijacker` (`CONNECT`) and `http.Flusher` (SSE)

- **Why it hits Go / Proxide:** Middleware wrapping `http.ResponseWriter` to capture status codes hides `http.Hijacker`, causing every `CONNECT` tunnel to fail with `http.ErrNotSupported`, and hides `http.Flusher`, breaking SSE streams.
- **Automated Catch:** Integration tests with middleware active over `CONNECT` and SSE.
- **Required Fix:** Implement `Unwrap() http.ResponseWriter` on custom wrappers and acquire hijacking/flushing via `http.NewResponseController(w)`.

### GP-21: `http.Request.Body` Is Single-Read (`io.ReadCloser`)

- **Why it hits Go / Proxide:** Reading `req.Body` to record a `CaptureEvent` or inspect it for rewrite drains the stream; forwarding `req` upstream afterward sends an empty `0`-byte body and hangs servers waiting for `Content-Length` bytes.
- **Automated Catch:** POST/PUT body-capture MITM integration tests.
- **Required Fix:** Capture up to `DefaultMaxBodyCaptureBytes` via `io.LimitReader`, then reconstruct `req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(captured), remainingBody))` (or full replaced buffer on rewrite).

### GP-22: Modifying Bodies Without Reconciling `Content-Length`, `Transfer-Encoding` & `Content-Encoding`

- **Why it hits Go / Proxide:** Rewriting a JSON body without updating `Content-Length` causes iOS/Android/Fire TV HTTP stacks to truncate the payload or hang awaiting missing bytes. Worse, rewriting a gzipped upstream body without decompressing or deleting `Content-Encoding: gzip` corrupts the client parser.
- **Automated Catch:** Integration tests asserting rewritten response lengths + gzip handling.
- **Required Fix:** In `internal/rewrite`, explicitly decode or reject compressed bodies when body-text rewrite applies, recalculate `Content-Length` (`resp.ContentLength = int64(len(newBody))`, `Header.Set("Content-Length", ...)`), and delete stale `Transfer-Encoding` / `Content-Encoding` headers when rewriting plaintext.

### GP-23: `http.Transport` Auto-Decompresses `gzip` by Default (`DisableCompression: false`)

- **Why it hits Go / Proxide:** By default, Go's `http.Transport` silently injects `Accept-Encoding: gzip` when absent, decompresses the response transparently, and deletes `Content-Encoding` and `Content-Length`. That corrupts wire fidelity and makes a transparent proxy lie about what the device actually sent and received.
- **Automated Catch:** Wire-fidelity proxy tests verifying `Accept-Encoding` and raw compressed payloads.
- **Required Fix:** Always configure the upstream proxy `http.Transport` with `DisableCompression: true`.

### GP-24: `http.Client.Do` Silently Follows `3xx` Redirects Instead of Returning Them to the Device

- **Why it hits Go / Proxide:** Calling `client.Do(req)` follows `301`/`302`/`307`/`308` redirects inside the proxy daemon, hiding redirect hops, breaking OAuth mobile deep-link callbacks (`myapp://callback`), and misattributing final responses to the original URL.
- **Automated Catch:** Integration test proxying a `302 Found` redirect.
- **Required Fix:** Always call `transport.RoundTrip(outReq)` directly in `internal/proxy` rather than `http.Client.Do`.

### GP-25: `http.Header` Key Canonicalization & `req.Host` Living Outside `req.Header`

- **Why it hits Go / Proxide:** Indexing `req.Header["x-proxide-client"]` directly returns `nil` because `net/http` canonicalizes keys (`X-Proxide-Client`). Meanwhile, HTTP's `Host` header is moved by `net/http.ReadRequest` out of `req.Header` into `req.Host`.
- **Automated Catch:** Unit tests checking case-insensitive header parsing and custom `Host` preservation.
- **Required Fix:** Always use `req.Header.Get(...)` / `Set(...)` / `Del(...)` (or `textproto.CanonicalMIMEHeaderKey`), and read/forward `req.Host` explicitly when reconstructing upstream requests.

### GP-26: Bidirectional `CONNECT` Tunnel Leaks a Goroutine on One-Sided Close

- **Why it hits Go / Proxide:** Spawning two `io.Copy` goroutines (`client -> upstream` and `upstream -> client`) and waiting for *both* deadlocks one goroutine indefinitely when only one peer sends `FIN` without closing its read side.
- **Automated Catch:** `go test -race` + goroutine count assertions after closing one side of a `CONNECT` tunnel.
- **Required Fix:** Propagate TCP half-close (`CloseWrite()`) on EOF, or close both connections on first error/completion under an `errgroup` so both copy goroutines exit promptly.

### GP-27: IPv4-Mapped IPv6 Addresses (`::ffff:192.168.1.42`) Fragment Device Tagging

- **Why it hits Go / Proxide:** Binding to dual-stack `0.0.0.0:8080` or `[::]:8080` on macOS/Linux causes `RemoteAddr` for IPv4 LAN clients to arrive as `[::ffff:192.168.1.42]:54321`, splitting one Fire TV across two `ClientIdentity` keys unless unmapped.
- **Automated Catch:** Unit tests covering IPv4, IPv4-mapped IPv6, and pure IPv6 `AddrPort` inputs.
- **Required Fix:** Parse peer addresses with `netip.ParseAddrPort` and always call `.Addr().Unmap()` before lookup or storage.

---

## 5. `crypto/tls` & `crypto/x509` MITM Footguns

### GP-28: Mutex Serialization & Thundering-Herd Signing Inside `tls.Config.GetCertificate`

- **Why it hits Go / Proxide:** Generating an asymmetric keypair and signing an X.509 leaf certificate inside a global cache mutex blocks every other device's TLS handshake on the LAN. Conversely, using an RWMutex without deduplication causes 20 parallel CDN connections from iOS/Android to generate 20 redundant leaf certs for the same SNI host simultaneously.
- **Automated Catch:** Concurrent `GetCertificate` race/benchmark tests verifying single invocation per cache miss.
- **Required Fix:** Check the bounded LRU cache under a short lock; on cache miss, deduplicate keygen/signing per normalized host via `golang.org/x/sync/singleflight` **outside** the LRU lock, then insert into the cache.

### GP-29: Missing SANs, Missing `ExtKeyUsageServerAuth`, Missing Clock-Skew Backdate, or `> 397d` Validity

- **Why it hits Go / Proxide:** Apple iOS/tvOS/macOS (`HT210176`), modern Android, and Go `crypto/x509` reject leaf certificates whose validity exceeds **397 days** (or 398-day policy boundary), lack `DNSNames` / `IPAddresses` SANs (relying only on `CommonName`), omit `x509.ExtKeyUsageServerAuth`, or fail `NotBefore` checks when a streaming stick's NTP clock lags by 1–2 minutes.
- **Automated Catch:** `internal/ca` unit tests verifying SANs, EKU, `NotBefore` backdate (`-5m`), and `NotAfter - NotBefore <= 397d`.
- **Required Fix:** Enforce `LeafClockSkewBackdate = 5 * time.Minute`, `DefaultLeafCertTTL = 7 * 24 * time.Hour`, `MaxAppleLeafCertTTL = 397 * 24 * time.Hour`, mandatory SAN population (`IPAddresses` vs `DNSNames` via `netip.ParseAddr`), and `ExtKeyUsageServerAuth`.

### GP-30: Sequential or Static Leaf Serial Numbers Collide Across Daemon Restarts

- **Why it hits Go / Proxide:** An in-memory counter starting at `1` resets on every `proxided` restart, issuing different leaf certificates for the same host with identical `(Issuer, SerialNumber)` pairs — causing strict browsers and Apple/Android TLS caches to reject connections with reused-serial errors.
- **Automated Catch:** Unit tests asserting unique 128-bit positive serials across calls.
- **Required Fix:** Generate positive 128-bit random serial numbers (`new(big.Int).Lsh(big.NewInt(1), 127)` bound) via `crypto/rand.Int` for every Root CA and leaf certificate.

### GP-31: Advertising `h2` ALPN on a Hijacked HTTP/1.1 MITM Connection Corrupts Framing

- **Why it hits Go / Proxide:** Copying upstream `NextProtos` (`[]string{"h2", "http/1.1"}`) blindly into the client-side `tls.Config` while feeding the decrypted connection to `http.ReadRequest` (HTTP/1.1 only) causes clients to send binary HTTP/2 prefaces (`PRI * HTTP/2.0`) that crash HTTP/1.1 parsing.
- **Automated Catch:** Loopback MITM integration test using an HTTP/2-capable TLS client.
- **Required Fix:** Restrict `tls.Config.NextProtos` to `[]string{"http/1.1"}` while the MITM handler reads HTTP/1.1 (or explicitly dispatch HTTP/2 frames via `golang.org/x/net/http2` only when `ConnectionState().NegotiatedProtocol == "h2"`).

### GP-32: Permissive `0644` CA Private Keys or Non-Atomic `os.WriteFile` Corruption

- **Why it hits Go / Proxide:** `os.WriteFile("ca-key.pem", keyBytes, 0o644)` exposes the Root CA private key to every local user on the machine, and crashing mid-write leaves a truncated key file on disk that bricks startup.
- **Automated Catch:** `gosec` (`G306`/`G302`), `internal/ca` filesystem mode unit tests (`0700` dir, `0600` key, `0644` cert).
- **Required Fix:** Create the CA directory with `0700`, write `ca-key.pem` to a temp file (`os.CreateTemp` / `0600`), flush/close, and promote via atomic `os.Rename` (never overwrite an existing valid CA).

---

## 6. `encoding/json` & I/O Decoding Footguns

### GP-33: `any` Decodes Numbers as `float64`, `[]byte` Encodes as Base64, and Unknown Fields Silently Drop

- **Why it hits Go / Proxide:** Unmarshaling dynamic JSON rules or API payloads into `map[string]any` silently turns 64-bit integer IDs into `float64` (losing precision above `2^53`); `[]byte` fields in structs serialize to base64 unless wrapped; and typos in `PUT /api/v1/rules` payloads (`"host_patern": ...`) silently succeed instead of returning `400 Bad Request`.
- **Automated Catch:** Control API unit tests verifying `400` on unknown fields and exact integer round-trips.
- **Required Fix:** Use concrete typed structs (never `any` for numeric rules), encode text previews explicitly as `string` alongside `body_base64` / `body_truncated`, and enable `dec.DisallowUnknownFields()` + `http.MaxBytesReader` on all Control API JSON decoders.

### GP-34: Unbounded `io.ReadAll` OOMs & Trailing JSON Tokens Are Silently Ignored

- **Why it hits Go / Proxide:** Calling `io.ReadAll(resp.Body)` on a 2 GB Fire TV OS update or HLS video stream crashes `proxided` with an out-of-memory panic. Meanwhile, `json.NewDecoder(r).Decode(&v)` reads only the first JSON value and ignores trailing garbage (`{"a":1}{"b":2}`).
- **Automated Catch:** Unit tests with oversized bodies (`> DefaultMaxBodyCaptureBytes`) and trailing-token payloads.
- **Required Fix:** Always wrap body captures with `io.LimitReader(r, limit+1)` (detecting truncation cleanly without buffering unbounded streams), and reject trailing tokens after `dec.Decode(&v)` by checking `dec.Decode(&struct{}{}) == io.EOF`.

---

## Quick-Reference Detection Matrix

| ID | Pitfall Summary | Category | Automated Catch | Required Fix |
| :--- | :--- | :--- | :--- | :--- |
| `GP-01` | Typed `nil` inside `error` interface | Type System | `golangci-lint` (`nilness`), unit test | Return untyped `nil` |
| `GP-02` | Slice sub-slicing & `append` backing-array mutation | Aliasing | `go test -race ./...` | `slices.Clone` or `s[:n:n]` |
| `GP-03` | Concurrent `map` read/write fatal crash | Concurrency | `go test -race ./...` | `sync.RWMutex` or `atomic.Pointer` snapshot |
| `GP-04` | `nil` map write panic / `nil` slice JSON `null` | Type System | Unit JSON contract tests | `make(map[K]V)` and non-nil `[]T{}` |
| `GP-05` | Copying `sync.Mutex` / `WaitGroup` by value | Concurrency | `go vet` (`copylocks`) | Pass owning structs by pointer |
| `GP-06` | Indexing `string` yields bytes, not runes | Strings | Fuzz tests + UTF-8 unit tests | Rune-aware truncation helpers |
| `GP-07` | Wrapping `ResponseWriter` hides `Hijacker`/`Flusher` | `net/http` | `CONNECT` + SSE integration tests | Implement `Unwrap()` + `ResponseController` |
| `GP-08` | `defer` inside loops leaks FDs/locks | `defer` | `gocritic` (`deferInLoop`) | Extract loop iteration helper |
| `GP-09` | `defer` evaluates arguments immediately | `defer` | Unit tests checking timings | Wrap dynamic args in closure |
| `GP-10` | `:=` shadowing `err` or `ctx` | Control Flow | `go vet -shadow` / `govet` | Assign with `=` or avoid inner redeclare |
| `GP-11` | `==` on wrapped errors | Errors | `golangci-lint` (`errorlint`) | Use `errors.Is` / `errors.As` |
| `GP-12` | `recover()` only catches current goroutine | Panics | Connection fault tests | `defer recoverPanic` in every goroutine |
| `GP-13` | Blocked channel send stalls proxy traffic | Channels | `go test -race` + leak test | Non-blocking `select` + drop counter |
| `GP-14` | Closing consumer channel / double close panics | Channels | `go test -race ./...` | Sender-only close + `done`/`ctx` |
| `GP-15` | `time.After` churn in hot `select` loops | Timers | `gocritic` / benchmarks | Reusable `time.NewTimer` + `Reset` |
| `GP-16` | `wg.Add(1)` inside spawned goroutine | Concurrency | `go test -race`, `go vet` | Call `wg.Add(1)` before `go func()` |
| `GP-17` | Reused read buffer racing across goroutines | Concurrency | `go test -race ./...` | Copy chunk with `slices.Clone` |
| `GP-18` | Global `WriteTimeout` kills `CONNECT`/SSE | `net/http` | Long-lived stream tests | `ReadHeaderTimeout` + `IdleTimeout` + `ctx` |
| `GP-19` | Unclosed/undrained `resp.Body` leaks sockets | `net/http` | `golangci-lint` (`bodyclose`) | Bounded drain + `defer resp.Body.Close()` |
| `GP-20` | Response wrappers break `ResponseController` | `net/http` | Middleware + `CONNECT` test | Forward `Unwrap() http.ResponseWriter` |
| `GP-21` | Single-read `req.Body` drains upstream payload | `net/http` | POST/PUT MITM tests | Restore `req.Body` after bounded capture |
| `GP-22` | Body rewrite without `Content-Length`/encoding sync | `net/http` | Rewrite integration tests | Recalculate `Content-Length` & encodings |
| `GP-23` | `Transport` auto-gunzips (`DisableCompression: false`) | `net/http` | Wire fidelity proxy tests | Set `DisableCompression: true` |
| `GP-24` | `http.Client.Do` silently follows `3xx` redirects | `net/http` | `302` redirect proxy test | Use `http.Transport.RoundTrip` directly |
| `GP-25` | Uncanonicalized `http.Header` & `req.Host` | `net/http` | Header/Host unit tests | Use `.Get`/`.Set`/`.Del` and `req.Host` |
| `GP-26` | Half-close `CONNECT` tunnel goroutine leak | `net.Conn` | `go test -race` + leak check | Propagate `CloseWrite()` / close peer |
| `GP-27` | `::ffff:` IPv4-mapped IPv6 splits client IDs | `net/netip` | Client IP normalization tests | `netip.ParseAddrPort` + `.Addr().Unmap()` |
| `GP-28` | Lock contention & thundering herd in `GetCertificate` | `crypto/tls` | Concurrent handshake test | LRU + `singleflight` outside cache lock |
| `GP-29` | Leaf cert rejected (`>397d`, no SANs/EKU, clock skew) | `crypto/x509` | Cert policy unit tests | SANs, `EKU`, `-5m` `NotBefore`, `<= 397d` |
| `GP-30` | Leaf serial collisions across restarts | `crypto/x509` | Serial uniqueness unit test | Positive 128-bit `crypto/rand` serials |
| `GP-31` | `h2` ALPN mismatch on HTTP/1.1 MITM reader | `crypto/tls` | HTTP/2 client MITM test | Pin `NextProtos` to served protocol |
| `GP-32` | Non-atomic `0644` CA private key writes | Security/I/O | `gosec`, file-mode unit tests | `0700` dir, `0600` temp + `os.Rename` |
| `GP-33` | `any` `float64` drift, base64 `[]byte`, silent fields | `encoding/json` | Strict API decoder tests | Typed structs + `DisallowUnknownFields()` |
| `GP-34` | Unbounded `io.ReadAll` OOM / trailing JSON tokens | I/O & JSON | Oversize + fuzz tests | `io.LimitReader` + `http.MaxBytesReader` + EOF |
