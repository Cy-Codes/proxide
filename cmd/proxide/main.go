package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"proxide/internal/api"
	"proxide/internal/bus"
	"proxide/internal/ca"
	"proxide/internal/clientreg"
	"proxide/internal/config"
	"proxide/internal/portal"
	"proxide/internal/proxy"
	"proxide/internal/rewrite"
	"proxide/internal/tlsmitm"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv))
}

func run(args []string, getenv func(string) string) int {
	cfg, err := config.LoadFromFlags(args, getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "proxide configuration error: %v\n", err)
		return 2
	}

	level := slog.LevelInfo
	if cfg.Debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	authority, err := ca.LoadOrCreate(ca.Options{
		Dir:       cfg.CADir,
		Algorithm: cfg.CAAlgorithm,
	})
	if err != nil {
		logger.Error("failed to initialize Root CA", "ca_dir", cfg.CADir, "err", err)
		return 1
	}

	clients := clientreg.NewRegistry(clientreg.Options{
		TagHeader:   cfg.ClientTagHeader,
		StripHeader: cfg.StripClientTag,
	})
	tlsMgr := tlsmitm.NewManager(tlsmitm.Options{
		Signer:           authority,
		LeafTTL:          cfg.LeafCertTTL,
		CacheSize:        cfg.CertCacheSize,
		PassthroughHosts: cfg.PassthroughHosts,
	})

	var localResolver rewrite.LocalFileResolver
	if cfg.MapLocalRoot != "" {
		localResolver = rewrite.NewOSRootResolver(cfg.MapLocalRoot)
	}
	rewriter, err := rewrite.NewEngine(localResolver, nil)
	if err != nil {
		logger.Error("failed to initialize rewrite engine", "err", err)
		return 1
	}

	evBus := bus.NewBus(cfg.SubscriberQueue)
	store := bus.NewRingStore(cfg.RingBufferFlows, cfg.RingBufferMaxBytes)

	_, proxyPort, _ := net.SplitHostPort(cfg.ProxyAddr)
	_, portalPort, _ := net.SplitHostPort(cfg.PortalAddr)
	lanAddrs, _ := config.ResolveLANAddresses(cfg.InterfaceName)
	primaryHost := "127.0.0.1"
	if len(lanAddrs) > 0 {
		primaryHost = lanAddrs[0].String()
	}

	portalHandler := portal.NewHandler(portal.Options{
		CAProvider: authority,
		ProxyHost:  primaryHost,
		ProxyPort:  proxyPort,
		PortalHost: cfg.PortalHost,
		PortalPort: portalPort,
	})

	proxyHandler := proxy.NewHandler(proxy.Options{
		Config:        cfg,
		Logger:        logger,
		Clients:       clients,
		TLSManager:    tlsMgr,
		Interceptor:   rewriter,
		PortalHandler: portalHandler,
		Store:         store,
		Publisher:     evBus,
	})

	apiHandler := api.NewHandler(api.Options{
		Config:     cfg,
		Logger:     logger,
		Store:      store,
		Subscriber: evBus,
		Clients:    clients,
		TLSManager: tlsMgr,
		RuleStore:  rewriter,
		CAProvider: authority,
	})

	proxySrv := &http.Server{
		Addr:              cfg.ProxyAddr,
		Handler:           proxyHandler,
		ReadHeaderTimeout: config.DefaultReadHeaderTimeout,
		IdleTimeout:       config.DefaultIdleTimeout,
	}
	portalSrv := &http.Server{
		Addr:              cfg.PortalAddr,
		Handler:           portalHandler,
		ReadHeaderTimeout: config.DefaultReadHeaderTimeout,
		WriteTimeout:      config.DefaultReadHeaderTimeout,
		IdleTimeout:       config.DefaultIdleTimeout,
	}
	apiSrv := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           apiHandler,
		ReadHeaderTimeout: config.DefaultReadHeaderTimeout,
		IdleTimeout:       config.DefaultIdleTimeout,
	}

	proxyLn, err := net.Listen("tcp", cfg.ProxyAddr)
	if err != nil {
		logger.Error("failed to bind proxy listener", "addr", cfg.ProxyAddr, "err", err)
		return 1
	}
	portalLn, err := net.Listen("tcp", cfg.PortalAddr)
	if err != nil {
		_ = proxyLn.Close()
		logger.Error("failed to bind setup portal listener", "addr", cfg.PortalAddr, "err", err)
		return 1
	}
	apiLn, err := net.Listen("tcp", cfg.APIAddr)
	if err != nil {
		_ = proxyLn.Close()
		_ = portalLn.Close()
		logger.Error("failed to bind loopback api listener", "addr", cfg.APIAddr, "err", err)
		return 1
	}

	logger.Info("proxide daemon started",
		"proxy_listen", proxyLn.Addr().String(),
		"portal_listen", portalLn.Addr().String(),
		"portal_virtual_url", "http://"+cfg.PortalHost,
		"api_listen", "http://"+apiLn.Addr().String(),
		"sse_stream", "http://"+apiLn.Addr().String()+"/api/v1/events/stream",
		"lan_primary_ip", primaryHost,
		"ca_fingerprint", authority.SHA256Fingerprint(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 3)
	var wg sync.WaitGroup
	serve := func(name string, srv *http.Server, ln net.Listener) {
		defer wg.Done()
		if sErr := srv.Serve(ln); sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("%s server: %w", name, sErr)
		}
	}

	wg.Add(3)
	go serve("proxy", proxySrv, proxyLn)
	go serve("portal", portalSrv, portalLn)
	go serve("api", apiSrv, apiLn)

	exitCode := 0
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case sErr := <-errCh:
		logger.Error("server exited unexpectedly", "err", sErr)
		exitCode = 1
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), config.DefaultShutdownTimeout)
	defer cancel()

	_ = proxySrv.Shutdown(shutdownCtx)
	_ = portalSrv.Shutdown(shutdownCtx)
	_ = apiSrv.Shutdown(shutdownCtx)

	proxyHandler.Close()
	evBus.Close()
	wg.Wait()
	return exitCode
}
