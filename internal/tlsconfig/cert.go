package tlsconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	certificateValidity = 10 * 365 * 24 * time.Hour
	certificateRenewal  = 30 * 24 * time.Hour
)

type CertificatePaths struct {
	CertFile string
	KeyFile  string
}

// CertificateFingerprint returns the colon-separated SHA-256 fingerprint of
// the first certificate in a PEM file. Clients can show the same value during
// first-use trust confirmation without exposing key material.
func CertificateFingerprint(certFile string) (string, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return "", fmt.Errorf("read TLS certificate: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("decode TLS certificate: no certificate PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse TLS certificate: %w", err)
	}
	digest := sha256.Sum256(cert.Raw)
	parts := make([]string, len(digest))
	for i, value := range digest {
		parts[i] = fmt.Sprintf("%02X", value)
	}
	return strings.Join(parts, ":"), nil
}

// DefaultCertificatePaths returns the per-user auto-generated TLS certificate paths.
func DefaultCertificatePaths(appName string) (CertificatePaths, error) {
	configRoot, err := os.UserConfigDir()
	if err != nil {
		return CertificatePaths{}, fmt.Errorf("resolve user config directory: %w", err)
	}

	root := filepath.Join(configRoot, appName, "tls")
	return CertificatePaths{
		CertFile: filepath.Join(root, "localhost.pem"),
		KeyFile:  filepath.Join(root, "localhost-key.pem"),
	}, nil
}

// DefaultServerHosts returns the hosts covered by the generated local certificate.
func DefaultServerHosts(extraHosts ...string) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if hostname, err := os.Hostname(); err == nil {
		hosts = append(hosts, hostname)
	}
	hosts = append(hosts, extraHosts...)
	return normalizeHosts(hosts)
}

// EnsureSelfSignedCertificate creates or reuses a local self-signed server certificate.
// It returns true when a new certificate/key pair was written.
func EnsureSelfSignedCertificate(certFile, keyFile string, hosts []string) (bool, error) {
	normalizedHosts := normalizeHosts(hosts)
	if len(normalizedHosts) == 0 {
		return false, fmt.Errorf("at least one TLS certificate host is required")
	}

	if certificateReusable(certFile, keyFile, normalizedHosts, time.Now()) {
		return false, nil
	}

	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		return false, fmt.Errorf("create TLS certificate directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(keyFile), 0o700); err != nil {
		return false, fmt.Errorf("create TLS key directory: %w", err)
	}

	certPEM, keyPEM, err := generateSelfSignedCertificate(normalizedHosts, time.Now())
	if err != nil {
		return false, err
	}

	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return false, fmt.Errorf("write TLS certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return false, fmt.Errorf("write TLS key: %w", err)
	}

	return true, nil
}

func certificateReusable(certFile, keyFile string, hosts []string, now time.Time) bool {
	if _, err := os.Stat(keyFile); err != nil {
		return false
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return false
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if now.Before(cert.NotBefore) || !cert.NotAfter.After(now.Add(certificateRenewal)) {
		return false
	}

	for _, host := range hosts {
		if err := cert.VerifyHostname(host); err != nil {
			return false
		}
	}
	return true
}

func generateSelfSignedCertificate(hosts []string, now time.Time) ([]byte, []byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate TLS private key: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("generate TLS certificate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "containerlab local HTTPS",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(certificateValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
			continue
		}
		template.DNSNames = append(template.DNSNames, host)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create TLS certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal TLS private key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func normalizeHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	normalized := make([]string, 0, len(hosts))
	for _, host := range hosts {
		candidate := normalizeHost(host)
		if candidate == "" {
			continue
		}
		key := strings.ToLower(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, candidate)
	}
	return normalized
}

func normalizeHost(raw string) string {
	host := strings.TrimSpace(raw)
	if host == "" {
		return ""
	}

	if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
		host = parsed.Host
	}

	trimmedHost := strings.Trim(host, "[]")
	if ip := net.ParseIP(trimmedHost); ip != nil {
		return trimmedHost
	}

	if splitHost, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(splitHost, "[]")
	}

	if strings.Count(host, ":") == 1 {
		name, port, found := strings.Cut(host, ":")
		if found {
			if _, err := strconv.Atoi(port); err == nil {
				host = name
			}
		}
	}

	return strings.Trim(strings.TrimSpace(host), "[]")
}
