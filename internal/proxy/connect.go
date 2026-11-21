package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxide/internal/config"
	"proxide/internal/model"
	"proxide/internal/portal"
	"proxide/internal/tlsmitm"
)

const connectEstablishedLine = "HTTP/1.1 200 Connection Established\r\n\r\n"

func (h *Handler) handleConnect(w http.ResponseWriter, r *http.Request) {
	start := time.Now().UTC()
	target := strings.TrimSpace(r.Host)
	if target == "" {
		target = strings.TrimSpace(r.URL.Host)
	}
	if target == "" {
		http.Error(w, "missing CONNECT target host", http.StatusBadRequest)
		return
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(target, "443")
	}
	normHost := tlsmitm.NormalizeHost(target)

	platform := portal.ClassifyUserAgent(r.Header.Get("User-Agent"))
	client := h.clients.Resolve(r.Context(), r.RemoteAddr, r.Header, platform)

	if h.tlsMgr == nil || h.tlsMgr.ShouldPassthrough(client.IP, normHost) {
		h.handleTunnel(w, r, start, client, target, normHost)
		return
	}
	h.handleMITM(w, r, start, client, normHost)
}

func (h *Handler) handleTunnel(
	w http.ResponseWriter,
	r *http.Request,
	start time.Time,
	client model.ClientIdentity,
	targetAddr string,
	normHost string,
) {
	dialStart := time.Now()
	dialer := net.Dialer{Timeout: config.DefaultDialTimeout}
	upstreamConn, err := dialer.DialContext(r.Context(), "tcp", targetAddr)
	if err != nil {
		http.Error(w, fmt.Sprintf("CONNECT dial failed: %v", err), http.StatusBadGateway)
		h.emitEvent(model.CaptureEvent{
			ID:        NewFlowID(start),
			Timestamp: start,
			Client:    client,
			Protocol:  model.ProtocolTunnel,
			Request: &model.HTTPRequestSnapshot{
				Method: http.MethodConnect,
				URL:    targetAddr,
				Host:   targetAddr,
			},
			TLS: &model.TLSInfo{
				SNI:         normHost,
				Passthrough: true,
			},
			Error: err.Error(),
		})
		return
	}
	connectMs := time.Since(dialStart).Milliseconds()
	defer func() { _ = upstreamConn.Close() }()

	rc := http.NewResponseController(w)
	clientConn, clientRW, err := rc.Hijack()
	if err != nil {
		http.Error(w, "CONNECT hijack unsupported", http.StatusInternalServerError)
		return
	}
	defer func() { _ = clientConn.Close() }()

	if _, err := clientRW.WriteString(connectEstablishedLine); err != nil {
		return
	}
	if err := clientRW.Flush(); err != nil {
		return
	}

	bytesUp, bytesDown := pumpBidirectional(r.Context(), clientConn, newBufferedConn(clientConn, clientRW.Reader), upstreamConn, upstreamConn)

	evt := model.CaptureEvent{
		ID:        NewFlowID(start),
		Timestamp: start,
		Client:    client,
		Protocol:  model.ProtocolTunnel,
		Request: &model.HTTPRequestSnapshot{
			Method: http.MethodConnect,
			URL:    targetAddr,
			Host:   targetAddr,
		},
		Response: &model.HTTPResponseSnapshot{
			Status:     http.StatusOK,
			StatusText: "Connection Established",
			Headers:    map[string][]string{},
		},
		Timing: model.FlowTiming{
			TCPConnectMs: connectMs,
			TotalMs:      time.Since(start).Milliseconds(),
		},
		TLS: &model.TLSInfo{
			SNI:         normHost,
			Passthrough: true,
		},
		BytesUp:   bytesUp,
		BytesDown: bytesDown,
	}
	h.emitEvent(evt)
	h.logger.InfoContext(r.Context(), "proxied CONNECT tunnel",
		"flow_id", evt.ID,
		"client_ip", evt.Client.IP.String(),
		"host", targetAddr,
		"passthrough", true,
		"duration_ms", evt.Timing.TotalMs,
	)
}

func (h *Handler) handleMITM(
	w http.ResponseWriter,
	r *http.Request,
	start time.Time,
	client model.ClientIdentity,
	fallbackHost string,
) {
	rc := http.NewResponseController(w)
	rawConn, clientRW, err := rc.Hijack()
	if err != nil {
		http.Error(w, "CONNECT hijack unsupported", http.StatusInternalServerError)
		return
	}
	if _, err := clientRW.WriteString(connectEstablishedLine); err != nil {
		_ = rawConn.Close()
		return
	}
	if err := clientRW.Flush(); err != nil {
		_ = rawConn.Close()
		return
	}

	// Preserve any already-buffered bytes inside clientRW.Reader before TLS handshake.
	connForTLS := newBufferedConn(rawConn, clientRW.Reader)
	tlsConn := tls.Server(connForTLS, h.tlsMgr.ServerTLSConfig(fallbackHost))
	defer func() { _ = tlsConn.Close() }()

	hsCtx, cancelHS := context.WithTimeout(r.Context(), config.DefaultTLSHandshakeTimeout)
	hsErr := tlsConn.HandshakeContext(hsCtx)
	cancelHS()

	state := tlsConn.ConnectionState()
	sni := tlsmitm.NormalizeHost(state.ServerName)
	if sni == "" {
		sni = fallbackHost
	}

	if hsErr != nil {
		pinSuspected := h.tlsMgr.RecordHandshakeFailure(client.IP, sni, hsErr)
		evt := model.CaptureEvent{
			ID:        NewFlowID(start),
			Timestamp: start,
			Client:    client,
			Protocol:  model.ProtocolHTTPS,
			Request: &model.HTTPRequestSnapshot{
				Method: http.MethodConnect,
				URL:    "https://" + sni,
				Host:   sni,
			},
			TLS: &model.TLSInfo{
				SNI:            sni,
				Passthrough:    false,
				PinSuspected:   pinSuspected,
				HandshakeError: hsErr.Error(),
			},
			Timing: model.FlowTiming{
				TotalMs: time.Since(start).Milliseconds(),
			},
			Error: hsErr.Error(),
		}
		h.emitEvent(evt)
		h.logger.WarnContext(r.Context(), "mitm tls handshake failed",
			"flow_id", evt.ID,
			"client_ip", client.IP.String(),
			"host", sni,
			"pin_suspected", pinSuspected,
			"err", hsErr,
		)
		return
	}

	tlsInfo := &model.TLSInfo{
		SNI:         sni,
		ALPN:        state.NegotiatedProtocol,
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		LeafSerial:  h.tlsMgr.LookupCachedSerial(sni),
		Passthrough: false,
	}

	br := bufio.NewReader(tlsConn)
	bw := bufio.NewWriter(tlsConn)

	// HTTP/1.1 keep-alive loop over decrypted TLS connection; each request runs inside serveMITMRequest.
	for {
		if r.Context().Err() != nil {
			return
		}
		keepAlive, ok := h.serveMITMRequest(r.Context(), tlsConn, br, bw, r.RemoteAddr, sni, tlsInfo)
		if !ok || !keepAlive {
			return
		}
	}
}

func (h *Handler) serveMITMRequest(
	ctx context.Context,
	tlsConn *tls.Conn,
	br *bufio.Reader,
	bw *bufio.Writer,
	remoteAddr string,
	sniHost string,
	tlsInfo *model.TLSInfo,
) (keepAlive bool, ok bool) {
	req, err := http.ReadRequest(br)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			h.logger.DebugContext(ctx, "mitm read request ended", "host", sniHost, "err", err)
		}
		return false, false
	}
	defer func() {
		if req.Body != nil {
			_ = req.Body.Close()
		}
	}()

	req = req.WithContext(ctx)
	req.RemoteAddr = remoteAddr
	if req.Host == "" {
		req.Host = sniHost
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}

	clientRequestedClose := req.Close || (req.ProtoMajor == 1 && req.ProtoMinor == 0)
	rw := newHijackedResponseWriter(tlsConn, br, bw, req.Method == http.MethodHead, clientRequestedClose)

	h.roundTripAndCapture(rw, req, model.ProtocolHTTPS, tlsInfo, "https")
	if rw.hijacked {
		return false, true
	}
	if err := rw.Finish(); err != nil {
		return false, false
	}
	return !clientRequestedClose && !rw.connClosed, true
}

type hijackedResponseWriter struct {
	conn        net.Conn
	br          *bufio.Reader
	bw          *bufio.Writer
	header      http.Header
	wroteHeader bool
	isHead      bool
	shouldClose bool
	connClosed  bool
	hijacked    bool
	chunked     io.WriteCloser
}

func newHijackedResponseWriter(conn net.Conn, br *bufio.Reader, bw *bufio.Writer, isHead, shouldClose bool) *hijackedResponseWriter {
	return &hijackedResponseWriter{
		conn:        conn,
		br:          br,
		bw:          bw,
		header:      make(http.Header),
		isHead:      isHead,
		shouldClose: shouldClose,
	}
}

func (w *hijackedResponseWriter) Header() http.Header {
	return w.header
}

func (w *hijackedResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true

	w.header.Del("Transfer-Encoding")
	if strings.EqualFold(w.header.Get("Connection"), "close") || w.shouldClose {
		w.header.Set("Connection", "close")
		w.connClosed = true
	} else {
		w.header.Set("Connection", "keep-alive")
	}

	allowsBody := code >= 200 && code != http.StatusNoContent && code != http.StatusNotModified && !w.isHead
	if allowsBody && w.header.Get("Content-Length") == "" {
		w.header.Set("Transfer-Encoding", "chunked")
		w.chunked = httputil.NewChunkedWriter(w.bw)
	}

	_, _ = fmt.Fprintf(w.bw, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	_ = w.header.Write(w.bw)
	_, _ = w.bw.WriteString("\r\n")
}

func (w *hijackedResponseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.isHead {
		return len(p), nil
	}
	if w.chunked != nil {
		return w.chunked.Write(p)
	}
	return w.bw.Write(p)
}

func (w *hijackedResponseWriter) Flush() {
	_ = w.bw.Flush()
}

func (w *hijackedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return w.conn, bufio.NewReadWriter(w.br, w.bw), nil
}

func (w *hijackedResponseWriter) Finish() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.chunked != nil {
		if err := w.chunked.Close(); err != nil {
			return err
		}
		if _, err := w.bw.WriteString("\r\n"); err != nil {
			return err
		}
	}
	return w.bw.Flush()
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func newBufferedConn(conn net.Conn, br *bufio.Reader) net.Conn {
	if br == nil || br.Buffered() == 0 {
		return conn
	}
	peeked, _ := br.Peek(br.Buffered())
	// Drain buffered prefix directly so post-hijack reads bypass net/http's connReader (which cancels r.Context() on EOF).
	return &bufferedConn{
		Conn: conn,
		r:    io.MultiReader(bytes.NewReader(slices.Clone(peeked)), conn),
	}
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func pumpBidirectional(
	ctx context.Context,
	clientConn net.Conn,
	clientReader io.Reader,
	upstreamConn io.Writer,
	upstreamCloser io.Closer,
) (int64, int64) {
	var bytesUp atomic.Int64
	var bytesDown atomic.Int64

	stopCancel := context.AfterFunc(ctx, func() {
		_ = clientConn.Close()
		_ = upstreamCloser.Close()
	})
	defer stopCancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer func() {
			if rec := recover(); rec != nil {
				_ = clientConn.Close()
				_ = upstreamCloser.Close()
			}
		}()
		n, err := io.Copy(upstreamConn, clientReader)
		bytesUp.Store(n)
		if err != nil {
			_ = clientConn.Close()
			_ = upstreamCloser.Close()
			return
		}
		propagateHalfClose(upstreamConn)
	}()

	go func() {
		defer wg.Done()
		defer func() {
			if rec := recover(); rec != nil {
				_ = clientConn.Close()
				_ = upstreamCloser.Close()
			}
		}()
		upstreamReader, ok := upstreamConn.(io.Reader)
		if !ok {
			return
		}
		n, err := io.Copy(clientConn, upstreamReader)
		bytesDown.Store(n)
		if err != nil {
			_ = clientConn.Close()
			_ = upstreamCloser.Close()
			return
		}
		propagateHalfClose(clientConn)
	}()

	wg.Wait()
	return bytesUp.Load(), bytesDown.Load()
}

func propagateHalfClose(dst any) {
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	if c, ok := dst.(io.Closer); ok {
		_ = c.Close()
	}
}
