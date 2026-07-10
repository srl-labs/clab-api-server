package tlsconfig

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnsureSelfSignedCertificateCreatesReusableCertificate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.pem")
	keyFile := filepath.Join(dir, "server-key.pem")
	hosts := []string{"localhost", "127.0.0.1", "::1", "api.example.test:8080"}

	generated, err := EnsureSelfSignedCertificate(certFile, keyFile, hosts)
	if err != nil {
		t.Fatalf("EnsureSelfSignedCertificate returned error: %v", err)
	}
	if !generated {
		t.Fatal("expected certificate generation")
	}

	cert := readCertificate(t, certFile)
	fingerprint, err := CertificateFingerprint(certFile)
	if err != nil {
		t.Fatalf("CertificateFingerprint returned error: %v", err)
	}
	digest := sha256.Sum256(cert.Raw)
	decodedFingerprint, err := hex.DecodeString(strings.ReplaceAll(fingerprint, ":", ""))
	if err != nil {
		t.Fatalf("decode certificate fingerprint: %v", err)
	}
	if !bytes.Equal(decodedFingerprint, digest[:]) {
		t.Fatalf("fingerprint mismatch: got %s", fingerprint)
	}
	for _, host := range []string{"localhost", "127.0.0.1", "::1", "api.example.test"} {
		if err := cert.VerifyHostname(host); err != nil {
			t.Fatalf("expected certificate to verify %q: %v", host, err)
		}
	}

	keyInfo, err := os.Stat(keyFile)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Fatalf("expected key mode 0600, got %v", keyInfo.Mode().Perm())
	}

	before := cert.NotAfter
	generated, err = EnsureSelfSignedCertificate(certFile, keyFile, hosts)
	if err != nil {
		t.Fatalf("second EnsureSelfSignedCertificate returned error: %v", err)
	}
	if generated {
		t.Fatal("expected existing certificate to be reused")
	}
	after := readCertificate(t, certFile).NotAfter
	if !after.Equal(before) {
		t.Fatalf("expected certificate to be reused, not regenerated: before=%s after=%s", before, after)
	}
}

func TestEnsureSelfSignedCertificateRegeneratesForMissingHost(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.pem")
	keyFile := filepath.Join(dir, "server-key.pem")

	if _, err := EnsureSelfSignedCertificate(certFile, keyFile, []string{"localhost"}); err != nil {
		t.Fatalf("initial EnsureSelfSignedCertificate returned error: %v", err)
	}
	first := readCertificate(t, certFile)
	time.Sleep(10 * time.Millisecond)

	generated, err := EnsureSelfSignedCertificate(certFile, keyFile, []string{"localhost", "api.example.test"})
	if err != nil {
		t.Fatalf("second EnsureSelfSignedCertificate returned error: %v", err)
	}
	if !generated {
		t.Fatal("expected regeneration for missing SAN")
	}

	second := readCertificate(t, certFile)
	if second.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("expected regenerated certificate to have a new serial number")
	}
	if err := second.VerifyHostname("api.example.test"); err != nil {
		t.Fatalf("expected regenerated certificate to verify new host: %v", err)
	}
}

func readCertificate(t *testing.T, certFile string) *x509.Certificate {
	t.Helper()

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("read cert file: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}
