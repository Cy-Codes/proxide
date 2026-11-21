package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"proxide/internal/config"
	"proxide/internal/model"
)

const (
	certFileName = "ca-cert.pem"
	keyFileName  = "ca-key.pem"
	rsaKeyBits   = 2048
)

// PublicProvider exposes read-only Root CA public metadata without private key access.
type PublicProvider interface {
	CertPEM() []byte
	CertDER() []byte
	SHA256Fingerprint() string
	NotAfter() time.Time
}

// Options configures Root CA generation or loading.
type Options struct {
	Dir       string
	Algorithm string
	Now       func() time.Time
}

// Authority manages the persistent local Root CA and signs dynamic leaf certificates.
type Authority struct {
	algorithm   string
	now         func() time.Time
	rootCert    *x509.Certificate
	rootKey     crypto.Signer
	certDER     []byte
	certPEM     []byte
	fingerprint string
}

// LoadOrCreate loads an existing valid Root CA from opts.Dir or atomically creates one if absent.
func LoadOrCreate(opts Options) (*Authority, error) {
	if strings.TrimSpace(opts.Dir) == "" {
		return nil, fmt.Errorf("%w: CA directory must not be empty", model.ErrInvalidConfig)
	}
	alg := opts.Algorithm
	if alg == "" {
		alg = config.DefaultCAAlgorithm
	}
	if alg != config.DefaultCAAlgorithm && alg != config.CAAlgorithmRSA2048 {
		return nil, fmt.Errorf("%w: unsupported CA algorithm %q", model.ErrInvalidConfig, alg)
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	if err := os.MkdirAll(opts.Dir, config.DirPermPrivate); err != nil {
		return nil, fmt.Errorf("create CA dir %q: %w", opts.Dir, err)
	}
	if err := os.Chmod(opts.Dir, config.DirPermPrivate); err != nil {
		return nil, fmt.Errorf("set permissions on CA dir %q: %w", opts.Dir, err)
	}

	certPath := filepath.Join(opts.Dir, certFileName)
	keyPath := filepath.Join(opts.Dir, keyFileName)

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)

	if certExists && keyExists {
		return loadExisting(certPath, keyPath, alg, nowFn)
	}
	if certExists != keyExists {
		return nil, fmt.Errorf("incomplete CA state in %q (certExists=%v keyExists=%v): remove or repair both files explicitly", opts.Dir, certExists, keyExists)
	}

	return createAndPersist(certPath, keyPath, alg, nowFn)
}

// CertPEM returns a defensive copy of the PEM-encoded public Root CA certificate.
func (a *Authority) CertPEM() []byte {
	return slices.Clone(a.certPEM)
}

// CertDER returns a defensive copy of the DER-encoded public Root CA certificate.
func (a *Authority) CertDER() []byte {
	return slices.Clone(a.certDER)
}

// SHA256Fingerprint returns the uppercase colon-separated SHA-256 fingerprint of the Root CA certificate.
func (a *Authority) SHA256Fingerprint() string {
	return a.fingerprint
}

// NotAfter returns the expiration timestamp of the Root CA certificate.
func (a *Authority) NotAfter() time.Time {
	return a.rootCert.NotAfter
}

// SignLeaf generates a fresh keypair and short-lived, SAN-compliant leaf certificate signed by this Root CA.
func (a *Authority) SignLeaf(host string, ttl time.Duration) (tls.Certificate, string, error) {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	normalized = strings.TrimPrefix(strings.TrimSuffix(normalized, "]"), "[")
	if normalized == "" {
		return tls.Certificate{}, "", errors.New("leaf certificate host must not be empty")
	}

	serial, err := RandomSerial()
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate leaf serial: %w", err)
	}

	leafKey, keyUsage, err := generateKeyPair(a.algorithm)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate leaf keypair: %w", err)
	}

	tmpl, err := BuildLeafTemplate(normalized, a.now().UTC(), ttl, serial, keyUsage)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, a.rootCert, leafKey.Public(), a.rootKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("sign leaf cert for %q: %w", normalized, err)
	}

	parsedLeaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("parse signed leaf cert for %q: %w", normalized, err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{leafDER, slices.Clone(a.certDER)},
		PrivateKey:  leafKey,
		Leaf:        parsedLeaf,
	}
	return tlsCert, hex.EncodeToString(serial.Bytes()), nil
}

// BuildLeafTemplate constructs a strictly policy-compliant X.509 leaf certificate template with zero I/O.
func BuildLeafTemplate(
	host string,
	now time.Time,
	ttl time.Duration,
	serial *big.Int,
	keyUsage x509.KeyUsage,
) (*x509.Certificate, error) {
	cleanHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	cleanHost = strings.TrimPrefix(strings.TrimSuffix(cleanHost, "]"), "[")
	if cleanHost == "" {
		return nil, errors.New("leaf certificate host must not be empty")
	}
	if ttl <= 0 || ttl > config.MaxAppleLeafCertTTL {
		return nil, fmt.Errorf("%w: got %s (max %s)", model.ErrInvalidLeafTTL, ttl, config.MaxAppleLeafCertTTL)
	}
	if serial == nil || serial.Sign() <= 0 {
		return nil, errors.New("leaf certificate serial must be positive")
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cleanHost,
			Organization: []string{"Proxide Local MITM"},
		},
		NotBefore:             now.Add(-config.LeafClockSkewBackdate),
		NotAfter:              now.Add(ttl),
		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	if ip, err := netip.ParseAddr(cleanHost); err == nil {
		unmapped := ip.Unmap()
		tmpl.IPAddresses = []net.IP{net.IP(unmapped.AsSlice())}
	} else {
		tmpl.DNSNames = []string{cleanHost}
	}
	return tmpl, nil
}

// RandomSerial returns a cryptographically random positive 128-bit certificate serial number.
func RandomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	maxOffset := new(big.Int).Sub(limit, big.NewInt(1))
	n, err := rand.Int(rand.Reader, maxOffset)
	if err != nil {
		return nil, err
	}
	return n.Add(n, big.NewInt(1)), nil
}

func createAndPersist(certPath, keyPath, alg string, nowFn func() time.Time) (*Authority, error) {
	signer, _, err := generateKeyPair(alg)
	if err != nil {
		return nil, fmt.Errorf("generate Root CA keypair: %w", err)
	}
	serial, err := RandomSerial()
	if err != nil {
		return nil, fmt.Errorf("generate Root CA serial: %w", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal Root CA public key: %w", err)
	}
	spkiHash := sha256.Sum256(spki)
	now := nowFn().UTC()

	rootTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "Proxide Local Root CA",
			Organization:       []string{"Proxide"},
			OrganizationalUnit: []string{"Local Development Proxy"},
		},
		NotBefore:             now.Add(-config.RootCAClockSkewBackdate),
		NotAfter:              now.Add(config.DefaultRootCATTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          spkiHash[:20],
	}

	certDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("sign self-signed Root CA: %w", err)
	}
	rootCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse created Root CA: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("marshal Root CA PKCS8 key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	if err := atomicWriteFile(keyPath, keyPEM, config.FilePermPrivateKey); err != nil {
		return nil, fmt.Errorf("persist Root CA private key: %w", err)
	}
	if err := atomicWriteFile(certPath, certPEM, config.FilePermPublicCert); err != nil {
		return nil, fmt.Errorf("persist Root CA certificate: %w", err)
	}

	return &Authority{
		algorithm:   alg,
		now:         nowFn,
		rootCert:    rootCert,
		rootKey:     signer,
		certDER:     certDER,
		certPEM:     certPEM,
		fingerprint: FormatSHA256Fingerprint(certDER),
	}, nil
}

func loadExisting(certPath, keyPath, alg string, nowFn func() time.Time) (*Authority, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read Root CA cert %q: %w", certPath, err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM certificate in %q", certPath)
	}
	rootCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Root CA cert %q: %w", certPath, err)
	}
	if !rootCert.IsCA {
		return nil, fmt.Errorf("certificate %q is not a CA certificate", certPath)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read Root CA key %q: %w", keyPath, err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid PEM private key in %q", keyPath)
	}
	signer, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Root CA key %q: %w", keyPath, err)
	}

	// Ensure private key public component matches the certificate before accepting it.
	if err := verifyKeyMatchesCert(signer, rootCert); err != nil {
		return nil, err
	}

	return &Authority{
		algorithm:   alg,
		now:         nowFn,
		rootCert:    rootCert,
		rootKey:     signer,
		certDER:     slices.Clone(certBlock.Bytes),
		certPEM:     slices.Clone(certPEM),
		fingerprint: FormatSHA256Fingerprint(certBlock.Bytes),
	}, nil
}

func parsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("parsed PKCS8 key does not implement crypto.Signer")
		}
		return signer, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key format")
}

func verifyKeyMatchesCert(signer crypto.Signer, cert *x509.Certificate) error {
	pubA, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("marshal signer public key: %w", err)
	}
	pubB, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal cert public key: %w", err)
	}
	if !slices.Equal(pubA, pubB) {
		return errors.New("Root CA private key does not match Root CA certificate")
	}
	return nil
}

func generateKeyPair(alg string) (crypto.Signer, x509.KeyUsage, error) {
	switch alg {
	case config.CAAlgorithmRSA2048:
		key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
		if err != nil {
			return nil, 0, err
		}
		return key, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, nil
	case config.DefaultCAAlgorithm:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, 0, err
		}
		return key, x509.KeyUsageDigitalSignature, nil
	default:
		return nil, 0, fmt.Errorf("%w: unsupported algorithm %q", model.ErrInvalidConfig, alg)
	}
}

// FormatSHA256Fingerprint formats raw DER bytes as uppercase colon-delimited SHA-256 hex.
func FormatSHA256Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	hexStr := strings.ToUpper(hex.EncodeToString(sum[:]))
	pairs := make([]string, 0, len(sum))
	for i := 0; i < len(hexStr); i += 2 {
		pairs = append(pairs, hexStr[i:i+2])
	}
	return strings.Join(pairs, ":")
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".proxide-ca-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
