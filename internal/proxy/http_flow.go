package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"proxide/internal/model"
	"proxide/internal/portal"
)

func (h *Handler) roundTripAndCapture(
	w http.ResponseWriter,
	r *http.Request,
	protocol model.FlowProtocol,
	tlsInfo *model.TLSInfo,
	defaultScheme string,
) {
	start := time.Now().UTC()
	flowID := NewFlowID(start)

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	if outReq.URL.Scheme == "" && defaultScheme != "" {
		outReq.URL.Scheme = defaultScheme
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = r.Host
	}
	if outReq.Host == "" {
		outReq.Host = outReq.URL.Host
	}

	platform := portal.ClassifyUserAgent(outReq.Header.Get("User-Agent"))
	client := h.clients.Resolve(r.Context(), r.RemoteAddr, outReq.Header, platform)

	wsUpgrade := IsWebSocketUpgrade(outReq.Header)
	StripHopByHopHeaders(outReq.Header)
	if wsUpgrade {
		outReq.Header.Set("Connection", "Upgrade")
		outReq.Header.Set("Upgrade", "websocket")
		if protocol == model.ProtocolHTTP {
			protocol = model.ProtocolWS
		} else if protocol == model.ProtocolHTTPS {
			protocol = model.ProtocolWSS
		}
	}

	reqBodyLimit := h.cfg.MaxBodyCaptureByte
	restoredBody, reqPreview, reqB64, reqBodyBytes, reqTrunc, readErr := ReadAndRestoreBody(
		outReq.Body,
		reqBodyLimit,
		outReq.Header.Get("Content-Type"),
	)
	if readErr != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		h.emitEvent(model.CaptureEvent{
			ID:        flowID,
			Timestamp: start,
			Client:    client,
			Protocol:  protocol,
			TLS:       tlsInfo.Clone(),
			Error:     readErr.Error(),
		})
		return
	}
	outReq.Body = restoredBody

	var timings flowTraceTimes
	tracedReq := outReq.WithContext(attachClientTrace(outReq.Context(), &timings))

	reqRes, err := h.interceptor.OnRequest(tracedReq.Context(), tracedReq, client)
	if err != nil {
		http.Error(w, "request manipulation failed", http.StatusBadGateway)
		h.emitEvent(model.CaptureEvent{
			ID:        flowID,
			Timestamp: start,
			Client:    client,
			Protocol:  protocol,
			Request:   buildRequestSnapshot(tracedReq, reqPreview, reqB64, reqBodyBytes, reqTrunc),
			TLS:       tlsInfo.Clone(),
			Error:     err.Error(),
		})
		return
	}

	reqSnapshot := buildRequestSnapshot(tracedReq, reqPreview, reqB64, reqBodyBytes, reqTrunc)
	manipulations := append([]model.AppliedManipulation{}, reqRes.Applied...)

	var resp *http.Response
	if reqRes.LocalResponse != nil {
		resp = reqRes.LocalResponse
	} else {
		timings.markReqStart()
		resp, err = h.transport.RoundTrip(tracedReq)
		if err != nil {
			statusCode := http.StatusBadGateway
			http.Error(w, fmt.Sprintf("upstream error: %v", err), statusCode)
			totalMs := time.Since(start).Milliseconds()
			h.emitEvent(model.CaptureEvent{
				ID:            flowID,
				Timestamp:     start,
				Client:        client,
				Protocol:      protocol,
				Request:       reqSnapshot,
				Timing:        timings.toFlowTiming(totalMs),
				TLS:           tlsInfo.Clone(),
				Manipulations: manipulations,
				Error:         err.Error(),
			})
			return
		}
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if reqRes.LocalResponse == nil {
		respApplied, respErr := h.interceptor.OnResponse(tracedReq.Context(), tracedReq, resp, client)
		if respErr != nil {
			http.Error(w, "response manipulation failed", http.StatusBadGateway)
			h.emitEvent(model.CaptureEvent{
				ID:            flowID,
				Timestamp:     start,
				Client:        client,
				Protocol:      protocol,
				Request:       reqSnapshot,
				Timing:        timings.toFlowTiming(time.Since(start).Milliseconds()),
				TLS:           tlsInfo.Clone(),
				Manipulations: manipulations,
				Error:         respErr.Error(),
			})
			return
		}
		manipulations = append(manipulations, respApplied...)
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		h.handleSwitchingProtocols(w, r, resp, flowID, start, client, protocol, reqSnapshot, tlsInfo, manipulations, &timings)
		return
	}

	respHeaders := resp.Header.Clone()
	StripHopByHopHeaders(respHeaders)
	CopyHeaders(w.Header(), respHeaders)

	contentType := respHeaders.Get("Content-Type")
	isSSE := strings.Contains(strings.ToLower(contentType), "text/event-stream")
	if isSSE {
		protocol = model.ProtocolSSE
	}

	capBody := newCapturingReadCloser(resp.Body, h.cfg.MaxBodyCaptureByte)
	w.WriteHeader(resp.StatusCode)

	var bytesDown int64
	if r.Method != http.MethodHead {
		if isSSE {
			bytesDown, err = streamFlushingCopy(w, capBody)
		} else {
			bytesDown, err = io.Copy(w, capBody)
		}
	}
	_ = capBody.Close()

	respPreview, respB64, respBodyBytes, respTrunc := capBody.Snapshot(contentType)
	totalMs := time.Since(start).Milliseconds()

	evt := model.CaptureEvent{
		ID:        flowID,
		Timestamp: start,
		Client:    client,
		Protocol:  protocol,
		Request:   reqSnapshot,
		Response: &model.HTTPResponseSnapshot{
			Status:        resp.StatusCode,
			StatusText:    http.StatusText(resp.StatusCode),
			Headers:       HeaderToMap(respHeaders),
			BodyPreview:   respPreview,
			BodyBase64:    respB64,
			BodyBytes:     respBodyBytes,
			BodyTruncated: respTrunc,
		},
		Timing:        timings.toFlowTiming(totalMs),
		TLS:           tlsInfo.Clone(),
		Manipulations: manipulations,
		BytesUp:       reqBodyBytes,
		BytesDown:     bytesDown,
	}
	if err != nil {
		evt.Error = err.Error()
	}

	h.emitEvent(evt)
	h.logger.InfoContext(r.Context(), "proxied http flow",
		"flow_id", evt.ID,
		"client_ip", evt.Client.IP.String(),
		"client_tag", evt.Client.Tag,
		"device_platform", evt.Client.Platform,
		"host", evt.Request.Host,
		"method", evt.Request.Method,
		"status", evt.Response.Status,
		"protocol", evt.Protocol,
		"duration_ms", evt.Timing.TotalMs,
	)
}

func (h *Handler) handleSwitchingProtocols(
	w http.ResponseWriter,
	r *http.Request,
	resp *http.Response,
	flowID string,
	start time.Time,
	client model.ClientIdentity,
	protocol model.FlowProtocol,
	reqSnapshot *model.HTTPRequestSnapshot,
	tlsInfo *model.TLSInfo,
	manipulations []model.AppliedManipulation,
	timings *flowTraceTimes,
) {
	upstreamRWC, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		http.Error(w, "upstream switching protocols body is not read-write", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstreamRWC.Close() }()

	rc := http.NewResponseController(w)
	clientConn, clientRW, err := rc.Hijack()
	if err != nil {
		http.Error(w, "failed to hijack client connection for upgrade", http.StatusBadGateway)
		return
	}
	defer func() { _ = clientConn.Close() }()

	if err := writeUpgradeResponse(clientRW, resp); err != nil {
		return
	}

	up, down := pumpUpgradeTunnel(r.Context(), clientConn, newBufferedConn(clientConn, clientRW.Reader), upstreamRWC)
	evt := model.CaptureEvent{
		ID:        flowID,
		Timestamp: start,
		Client:    client,
		Protocol:  protocol,
		Request:   reqSnapshot,
		Response: &model.HTTPResponseSnapshot{
			Status:     resp.StatusCode,
			StatusText: http.StatusText(resp.StatusCode),
			Headers:    HeaderToMap(resp.Header),
		},
		Timing:        timings.toFlowTiming(time.Since(start).Milliseconds()),
		TLS:           tlsInfo.Clone(),
		Manipulations: manipulations,
		BytesUp:       up,
		BytesDown:     down,
	}
	h.emitEvent(evt)
}

func writeUpgradeResponse(bw *bufio.ReadWriter, resp *http.Response) error {
	if _, err := fmt.Fprintf(bw, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode)); err != nil {
		return err
	}
	if err := resp.Header.Write(bw); err != nil {
		return err
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	return bw.Flush()
}

func streamFlushingCopy(w http.ResponseWriter, src io.Reader) (int64, error) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 4096)
	var total int64
	// Bounded SSE chunk loop: flushes each server-sent chunk promptly until EOF or write failure.
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := w.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			_ = rc.Flush()
		}
		if readErr != nil {
			if readErr == io.EOF {
				return total, nil
			}
			return total, readErr
		}
	}
}

func buildRequestSnapshot(req *http.Request, preview, b64 string, totalBytes int64, truncated bool) *model.HTTPRequestSnapshot {
	return &model.HTTPRequestSnapshot{
		Method:        req.Method,
		URL:           req.URL.String(),
		Host:          req.Host,
		Path:          req.URL.RequestURI(),
		Headers:       HeaderToMap(req.Header),
		BodyPreview:   preview,
		BodyBase64:    b64,
		BodyBytes:     totalBytes,
		BodyTruncated: truncated,
	}
}

type flowTraceTimes struct {
	dnsStart     time.Time
	dnsDur       time.Duration
	connectStart time.Time
	connectDur   time.Duration
	tlsStart     time.Time
	tlsDur       time.Duration
	reqStart     time.Time
	ttfbDur      time.Duration
}

func (f *flowTraceTimes) markReqStart() {
	f.reqStart = time.Now()
}

func (f *flowTraceTimes) toFlowTiming(totalMs int64) model.FlowTiming {
	return model.FlowTiming{
		DNSMs:          f.dnsDur.Milliseconds(),
		TCPConnectMs:   f.connectDur.Milliseconds(),
		TLSHandshakeMs: f.tlsDur.Milliseconds(),
		TTFBMs:         f.ttfbDur.Milliseconds(),
		TotalMs:        totalMs,
	}
}

func attachClientTrace(ctx context.Context, t *flowTraceTimes) context.Context {
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			t.dnsStart = time.Now()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !t.dnsStart.IsZero() {
				t.dnsDur = time.Since(t.dnsStart)
			}
		},
		ConnectStart: func(_, _ string) {
			t.connectStart = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			if !t.connectStart.IsZero() {
				t.connectDur = time.Since(t.connectStart)
			}
		},
		TLSHandshakeStart: func() {
			t.tlsStart = time.Now()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !t.tlsStart.IsZero() {
				t.tlsDur = time.Since(t.tlsStart)
			}
		},
		GotFirstResponseByte: func() {
			if !t.reqStart.IsZero() {
				t.ttfbDur = time.Since(t.reqStart)
			}
		},
	}
	return httptrace.WithClientTrace(ctx, trace)
}

func pumpUpgradeTunnel(ctx context.Context, clientConn net.Conn, clientReader io.Reader, upstream io.ReadWriteCloser) (int64, int64) {
	return pumpBidirectional(ctx, clientConn, clientReader, upstream, upstream)
}
