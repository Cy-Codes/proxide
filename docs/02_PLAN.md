# Proxide — UI, Inspector Client & Tooling Plan (`02_PLAN`)

> **Scope:** Covers the decoupled inspector clients, interactive traffic manipulation UI, `adb` CLI automation, WebSocket stream upgrade, and repository developer-experience tooling built on top of the `proxide` daemon contracts defined in [01_PLAN.md](01_PLAN.md). Every client component MUST consume only `internal/model` and the loopback Control API (`127.0.0.1:9090`), never daemon proxy/TLS internals.

---

## Phase Progress Dashboard

| Workstream | Target Surface | Status | Key Verification Gate | Target Date |
| :--- | :--- | :--- | :--- | :--- |
| **UI-1: Terminal Inspector & CLI (`cmd/proxide-tui` / `cmd/proxide inspect`)** | Live TUI stream + filter by client IP/tag/platform + `adb` proxy helper | Not Started | Connects strictly to `/api/v1/events/stream` & `/api/v1/flows`; `internal/archtest` passes | — |
| **UI-2: WebSocket Upgrade & Interactive Rule Editor** | Bi-directional WS event stream + CRUD routes (`POST`/`PUT`/`DELETE /api/v1/rules/{id}`) | Not Started | Live rule toggling, Map Local root-jail UI, and slow-subscriber non-blocking tests pass | — |
| **UI-3: Optional Local Web / Desktop Inspector UI** | Browser or native desktop UI served separately from `0.0.0.0` proxy port | Not Started | Loopback-only binding enforced; live MITM flow detail, syntax highlighting & HAR export | — |
| **DX-1: Repo Formatting & Hook Governance** | `.editorconfig`, `.golangci.yml`, `.githooks/pre-commit`, `scripts/lib.sh` | Not Started | `golangci-lint run`, `shfmt`, `shellcheck`, and pre-commit auto-clean pass | — |

---

## Planned Workstreams

### 1. Terminal UI & `adb` Device Helper (`UI-1`)
- [ ] Add interactive live-tail TUI client consuming `GET /api/v1/events/stream` (SSE / WebSocket) and `GET /api/v1/flows`.
- [ ] Add client filter switcher grouped by `ClientIdentity` (`IP`, `Tag`, `FriendlyName`, `MAC`, `Platform`) plus alias renaming (`PUT /api/v1/clients/{ip}`).
- [ ] Surface `PinSuspected` alerts inline with a one-keystroke action to add the domain to `PUT /api/v1/passthrough`.
- [ ] Implement `adb` proxy automation helpers (`adb set`, `adb clear`, `adb status`, `adb push-ca`) wrapping `adb shell settings put global http_proxy`.

### 2. WebSocket Stream & Granular Rule Endpoints (`UI-2`)
- [ ] Add WebSocket transport option alongside SSE on `GET /api/v1/events/stream` plus per-rule endpoints (`POST /api/v1/rules`, `PUT /api/v1/rules/{id}`, `DELETE /api/v1/rules/{id}`).
- [ ] Add WebSocket / SSE frame capture rendering inside `CaptureEvent.StreamFrames` for live streaming protocols.
- [ ] Add HAR 1.2 & redacted JSON capture export helpers leveraging `proxy.RedactSensitiveHeaders`.

### 3. Local Web / Desktop Inspector View (`UI-3`)
- [ ] Build a clean web or native desktop UI consuming the loopback REST + stream API (`127.0.0.1:9090`) with zero coupling to `internal/proxy`, `internal/ca`, or `internal/tlsmitm`.
- [ ] Render request/response headers, decoded previews, timing waterfall (`DNSMs`, `TCPConnectMs`, `TLSHandshakeMs`, `TTFBMs`, `TotalMs`), and applied manipulation badges (`AppliedManipulation`).
- [ ] Provide interactive Map Local fixture picker (bounded strictly beneath `--map-local-root`) and header/body rewrite rule builder.

### 4. Repository Governance & Linting (`DX-1`)
- [ ] Create `.editorconfig`, `.golangci.yml`, `scripts/lib.sh`, and `.githooks/pre-commit` (+ `.githooks/install-hooks.sh`) enforcing `gofmt`/`goimports`, unused-import removal, CA private key commit blocking, `go vet ./...`, and `internal/archtest`.
