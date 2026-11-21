package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"proxide/internal/bus"
	"proxide/internal/ca"
	"proxide/internal/clientreg"
	"proxide/internal/config"
	"proxide/internal/model"
	"proxide/internal/rewrite"
	"proxide/internal/tlsmitm"
)

const sseKeepAliveInterval = 15 * time.Second

// Options configures the loopback Control & Inspection API HTTP handler.
type Options struct {
	Config     config.Config
	Logger     *slog.Logger
	Store      bus.FlowStore
	Subscriber bus.Subscriber
	Clients    clientreg.Resolver
	TLSManager tlsmitm.ManagerInterface
	RuleStore  rewrite.RuleStore
	CAProvider ca.PublicProvider
}

// Handler serves versioned loopback REST and SSE inspection endpoints.
type Handler struct {
	cfg        config.Config
	logger     *slog.Logger
	store      bus.FlowStore
	subscriber bus.Subscriber
	clients    clientreg.Resolver
	tlsMgr     tlsmitm.ManagerInterface
	rules      rewrite.RuleStore
	ca         ca.PublicProvider
	mux        *http.ServeMux
}

// NewHandler builds a dedicated ServeMux-backed Handler without mutating http.DefaultServeMux.
func NewHandler(opts Options) *Handler {
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	h := &Handler{
		cfg:        opts.Config,
		logger:     logger,
		store:      opts.Store,
		subscriber: opts.Subscriber,
		clients:    opts.Clients,
		tlsMgr:     opts.TLSManager,
		rules:      opts.RuleStore,
		ca:         opts.CAProvider,
		mux:        http.NewServeMux(),
	}

	h.mux.HandleFunc("GET /api/v1/health", h.handleHealth)
	h.mux.HandleFunc("GET /api/v1/flows", h.handleListFlows)
	h.mux.HandleFunc("GET /api/v1/flows/{id}", h.handleGetFlow)
	h.mux.HandleFunc("DELETE /api/v1/flows", h.handleClearFlows)
	h.mux.HandleFunc("GET /api/v1/events/stream", h.handleEventStream)
	h.mux.HandleFunc("GET /api/v1/clients", h.handleListClients)
	h.mux.HandleFunc("PUT /api/v1/clients/{ip}", h.handleSetClientAlias)
	h.mux.HandleFunc("GET /api/v1/passthrough", h.handleGetPassthrough)
	h.mux.HandleFunc("PUT /api/v1/passthrough", h.handlePutPassthrough)
	h.mux.HandleFunc("GET /api/v1/rules", h.handleGetRules)
	h.mux.HandleFunc("PUT /api/v1/rules", h.handlePutRules)
	h.mux.HandleFunc("/", h.handleNotFound)
	return h
}

// ServeHTTP enforces optional bearer authentication and delegates to the isolated ServeMux.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.cfg.APIToken != "" {
		if !h.authorized(r) {
			writeAPIError(w, http.StatusUnauthorized, model.ApiError{
				Code:    model.ErrCodeUnauthorized,
				Message: "missing or invalid bearer token",
				TraceID: newTraceID(),
			})
			return
		}
	}
	h.mux.ServeHTTP(w, r)
}

func (h *Handler) authorized(r *http.Request) bool {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return false
	}
	presented := strings.TrimPrefix(authHeader, prefix)
	return subtle.ConstantTimeCompare([]byte(presented), []byte(h.cfg.APIToken)) == 1
}

type healthResponse struct {
	Status        string         `json:"status"`
	ProxyAddr     string         `json:"proxy_addr"`
	PortalAddr    string         `json:"portal_addr"`
	PortalHost    string         `json:"portal_host"`
	CAFingerprint string         `json:"ca_fingerprint,omitempty"`
	Store         bus.StoreStats `json:"store"`
	Bus           bus.BusStats   `json:"bus"`
}

func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	resp := healthResponse{
		Status:     "ok",
		ProxyAddr:  h.cfg.ProxyAddr,
		PortalAddr: h.cfg.PortalAddr,
		PortalHost: h.cfg.PortalHost,
	}
	if h.ca != nil {
		resp.CAFingerprint = h.ca.SHA256Fingerprint()
	}
	if h.store != nil {
		resp.Store = h.store.Stats()
	}
	if h.subscriber != nil {
		resp.Bus = h.subscriber.Stats()
	}
	writeJSON(w, http.StatusOK, resp)
}

type flowsResponse struct {
	Flows []model.CaptureEvent `json:"flows"`
	Stats bus.StoreStats       `json:"stats"`
}

func (h *Handler) handleListFlows(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, flowsResponse{Flows: []model.CaptureEvent{}})
		return
	}
	q := r.URL.Query()
	filter := bus.FlowFilter{
		ClientTag: strings.TrimSpace(q.Get("client_tag")),
		Host:      strings.TrimSpace(q.Get("host")),
		Method:    strings.TrimSpace(q.Get("method")),
		CursorID:  strings.TrimSpace(q.Get("cursor")),
	}
	if rawIP := strings.TrimSpace(q.Get("client_ip")); rawIP != "" {
		ip, err := netip.ParseAddr(rawIP)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, model.ApiError{
				Code:        model.ErrCodeValidation,
				Message:     "invalid client_ip query parameter",
				FieldErrors: []model.FieldViolation{{Field: "client_ip", Message: err.Error()}},
			})
			return
		}
		filter.ClientIP = ip.Unmap()
	}
	if rawStatus := strings.TrimSpace(q.Get("status")); rawStatus != "" {
		st, err := strconv.Atoi(rawStatus)
		if err != nil || st < 100 || st > 599 {
			writeAPIError(w, http.StatusBadRequest, model.ApiError{
				Code:        model.ErrCodeValidation,
				Message:     "invalid status query parameter",
				FieldErrors: []model.FieldViolation{{Field: "status", Message: "must be an HTTP status code 100..599"}},
			})
			return
		}
		filter.Status = st
	}
	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		lim, err := strconv.Atoi(rawLimit)
		if err != nil || lim <= 0 {
			writeAPIError(w, http.StatusBadRequest, model.ApiError{
				Code:        model.ErrCodeValidation,
				Message:     "invalid limit query parameter",
				FieldErrors: []model.FieldViolation{{Field: "limit", Message: "must be a positive integer"}},
			})
			return
		}
		filter.Limit = lim
	}

	flows := h.store.List(filter)
	if flows == nil {
		flows = []model.CaptureEvent{}
	}
	writeJSON(w, http.StatusOK, flowsResponse{
		Flows: flows,
		Stats: h.store.Stats(),
	})
}

func (h *Handler) handleGetFlow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if h.store == nil || id == "" {
		writeAPIError(w, http.StatusNotFound, model.ApiError{
			Code:    model.ErrCodeNotFound,
			Message: "flow not found",
		})
		return
	}
	ev, ok := h.store.Get(id)
	if !ok {
		writeAPIError(w, http.StatusNotFound, model.ApiError{
			Code:    model.ErrCodeNotFound,
			Message: "flow not found",
		})
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (h *Handler) handleClearFlows(w http.ResponseWriter, _ *http.Request) {
	if h.store != nil {
		h.store.Clear()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleEventStream(w http.ResponseWriter, r *http.Request) {
	if h.subscriber == nil {
		writeAPIError(w, http.StatusInternalServerError, h.internalError("event stream unavailable", nil))
		return
	}

	q := r.URL.Query()
	filter := bus.EventFilter{
		ClientTag: strings.TrimSpace(q.Get("client_tag")),
		Host:      strings.TrimSpace(q.Get("host")),
		Method:    strings.TrimSpace(q.Get("method")),
	}
	if rawIP := strings.TrimSpace(q.Get("client_ip")); rawIP != "" {
		ip, err := netip.ParseAddr(rawIP)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, model.ApiError{
				Code:        model.ErrCodeValidation,
				Message:     "invalid client_ip query parameter",
				FieldErrors: []model.FieldViolation{{Field: "client_ip", Message: err.Error()}},
			})
			return
		}
		filter.ClientIP = ip.Unmap()
	}

	ch, unsub := h.subscriber.Subscribe(r.Context(), filter)
	defer unsub()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)
	_, _ = io.WriteString(w, ": connected\n\n")
	_ = rc.Flush()

	keepalive := time.NewTimer(sseKeepAliveInterval)
	defer keepalive.Stop()

	// Bounded by r.Context().Done() and bus channel closure (GP-15 reusable timer).
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			encoded, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "event: flow\ndata: %s\n\n", encoded); err != nil {
				return
			}
			_ = rc.Flush()
			if !keepalive.Stop() {
				select {
				case <-keepalive.C:
				default:
				}
			}
			keepalive.Reset(sseKeepAliveInterval)
		case <-keepalive.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
			keepalive.Reset(sseKeepAliveInterval)
		}
	}
}

type clientsResponse struct {
	Clients []model.ClientRecord `json:"clients"`
}

func (h *Handler) handleListClients(w http.ResponseWriter, _ *http.Request) {
	var list []model.ClientRecord
	if h.clients != nil {
		list = h.clients.List()
	}
	if list == nil {
		list = []model.ClientRecord{}
	}
	writeJSON(w, http.StatusOK, clientsResponse{Clients: list})
}

type setAliasRequest struct {
	FriendlyName string `json:"friendly_name"`
}

func (h *Handler) handleSetClientAlias(w http.ResponseWriter, r *http.Request) {
	ip, err := netip.ParseAddr(strings.TrimSpace(r.PathValue("ip")))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, model.ApiError{
			Code:        model.ErrCodeValidation,
			Message:     "invalid client IP path parameter",
			FieldErrors: []model.FieldViolation{{Field: "ip", Message: err.Error()}},
		})
		return
	}
	var req setAliasRequest
	if status, apiErr := decodeStrictJSON(w, r, &req); apiErr != nil {
		writeAPIError(w, status, *apiErr)
		return
	}
	if h.clients == nil {
		writeAPIError(w, http.StatusInternalServerError, h.internalError("client registry unavailable", nil))
		return
	}
	rec := h.clients.SetAlias(ip, req.FriendlyName)
	writeJSON(w, http.StatusOK, rec)
}

func (h *Handler) handleGetPassthrough(w http.ResponseWriter, _ *http.Request) {
	if h.tlsMgr == nil {
		writeJSON(w, http.StatusOK, tlsmitm.PassthroughState{
			Hosts:         []string{},
			ClientIPs:     []netip.Addr{},
			SuspectedPins: []tlsmitm.PinObservation{},
		})
		return
	}
	writeJSON(w, http.StatusOK, h.tlsMgr.PassthroughSnapshot())
}

type putPassthroughRequest struct {
	Hosts     []string `json:"hosts"`
	ClientIPs []string `json:"client_ips"`
}

func (h *Handler) handlePutPassthrough(w http.ResponseWriter, r *http.Request) {
	var req putPassthroughRequest
	if status, apiErr := decodeStrictJSON(w, r, &req); apiErr != nil {
		writeAPIError(w, status, *apiErr)
		return
	}
	ips := make([]netip.Addr, 0, len(req.ClientIPs))
	for idx, raw := range req.ClientIPs {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, model.ApiError{
				Code:        model.ErrCodeValidation,
				Message:     "invalid passthrough client IP",
				FieldErrors: []model.FieldViolation{{Field: fmt.Sprintf("client_ips[%d]", idx), Message: err.Error()}},
			})
			return
		}
		ips = append(ips, addr.Unmap())
	}
	if h.tlsMgr != nil {
		h.tlsMgr.UpdatePassthrough(req.Hosts, ips)
		writeJSON(w, http.StatusOK, h.tlsMgr.PassthroughSnapshot())
		return
	}
	writeJSON(w, http.StatusOK, tlsmitm.PassthroughState{
		Hosts:         []string{},
		ClientIPs:     ips,
		SuspectedPins: []tlsmitm.PinObservation{},
	})
}

type rulesEnvelope struct {
	Rules []model.RewriteRule `json:"rules"`
}

func (h *Handler) handleGetRules(w http.ResponseWriter, _ *http.Request) {
	if h.rules == nil {
		writeJSON(w, http.StatusOK, rulesEnvelope{Rules: []model.RewriteRule{}})
		return
	}
	writeJSON(w, http.StatusOK, rulesEnvelope{Rules: h.rules.ListRules()})
}

func (h *Handler) handlePutRules(w http.ResponseWriter, r *http.Request) {
	var req rulesEnvelope
	if status, apiErr := decodeStrictJSON(w, r, &req); apiErr != nil {
		writeAPIError(w, status, *apiErr)
		return
	}
	if h.rules == nil {
		writeAPIError(w, http.StatusInternalServerError, h.internalError("rule store unavailable", nil))
		return
	}
	if err := h.rules.ReplaceRules(req.Rules); err != nil {
		switch {
		case errors.Is(err, model.ErrRuleConflict):
			writeAPIError(w, http.StatusConflict, model.ApiError{
				Code:    model.ErrCodeConflict,
				Message: err.Error(),
			})
		case errors.Is(err, model.ErrInvalidConfig):
			writeAPIError(w, http.StatusBadRequest, model.ApiError{
				Code:    model.ErrCodeValidation,
				Message: err.Error(),
			})
		default:
			writeAPIError(w, http.StatusInternalServerError, h.internalError("failed to update rules", err))
		}
		return
	}
	writeJSON(w, http.StatusOK, rulesEnvelope{Rules: h.rules.ListRules()})
}

func (h *Handler) handleNotFound(w http.ResponseWriter, _ *http.Request) {
	writeAPIError(w, http.StatusNotFound, model.ApiError{
		Code:    model.ErrCodeNotFound,
		Message: "endpoint not found",
	})
}

func (h *Handler) internalError(msg string, err error) model.ApiError {
	traceID := newTraceID()
	if err != nil {
		h.logger.Error("api internal error", "trace_id", traceID, "err", err)
	}
	detail := msg
	if h.cfg.Debug && err != nil {
		detail = fmt.Sprintf("%s: %v", msg, err)
	}
	return model.ApiError{
		Code:    model.ErrCodeInternal,
		Message: detail,
		TraceID: traceID,
	}
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, dst any) (int, *model.ApiError) {
	r.Body = http.MaxBytesReader(w, r.Body, config.DefaultMaxAPIRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return http.StatusRequestEntityTooLarge, &model.ApiError{
				Code:    model.ErrCodePayloadTooLarge,
				Message: fmt.Sprintf("request body exceeds %d byte limit", config.DefaultMaxAPIRequestBytes),
			}
		}
		return http.StatusBadRequest, &model.ApiError{
			Code:    model.ErrCodeValidation,
			Message: fmt.Sprintf("invalid JSON body: %v", err),
		}
	}

	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return http.StatusBadRequest, &model.ApiError{
			Code:    model.ErrCodeValidation,
			Message: "unexpected trailing data after JSON object",
		}
	}
	return 0, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, model.ApiError{
			Code:    model.ErrCodeInternal,
			Message: "failed to encode JSON response",
			TraceID: newTraceID(),
		})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func writeAPIError(w http.ResponseWriter, status int, apiErr model.ApiError) {
	encoded, err := json.Marshal(apiErr)
	if err != nil {
		http.Error(w, http.StatusText(status), status)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func newTraceID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
