package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testClientCertificate(t *testing.T) *tls.Certificate {
	t.Helper()
	now := time.Now()
	leaf, key := prerequisiteCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "Test client"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, nil, nil)
	return &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}
}

func TestAuthenticationConfigCopiesAndRejectsConflicts(t *testing.T) {
	cert := testClientCertificate(t)
	cert.OCSPStaple = []byte("ocsp")
	cert.SignedCertificateTimestamps = [][]byte{[]byte("timestamp")}
	prepared, err := PrepareAuthentication(Config{Auth: AuthMTLSExternal, ClientCertificate: cert, TLSMode: "required"})
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate[0][0] ^= 1
	cert.OCSPStaple[0] ^= 1
	cert.SignedCertificateTimestamps[0][0] ^= 1
	cert.Leaf.Subject.CommonName = "mutated"
	if bytes.Equal(prepared.ClientCertificate.Certificate[0], cert.Certificate[0]) ||
		bytes.Equal(prepared.ClientCertificate.OCSPStaple, cert.OCSPStaple) ||
		prepared.ClientCertificate.Leaf.Subject.CommonName != "Test client" {
		t.Fatal("client TLS input was not independently copied")
	}
	if err := validateClientCertificate(prepared.ClientCertificate, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []Config{
		{Auth: "invalid"},
		{Auth: AuthMTLS},
		{Auth: AuthGSSAPI, ClientCertificate: prepared.ClientCertificate},
		{Auth: AuthMTLS, ClientCertificate: prepared.ClientCertificate, TLSMode: "off"},
		{TLSMode: "off", ServerTrust: ServerTrust{InsecureAllowUnverifiableIssuer: true}},
		{Auth: AuthMTLS, ClientCertificate: &tls.Certificate{Certificate: [][]byte{[]byte("bad")}}},
	} {
		if _, err := PrepareAuthentication(invalid); err == nil {
			t.Fatalf("invalid auth config accepted: %+v", invalid)
		}
	}
	fresh := testClientCertificate(t)
	fresh.PrivateKey = testClientCertificate(t).PrivateKey
	if _, err := PrepareAuthentication(Config{Auth: AuthMTLS, ClientCertificate: fresh}); err == nil {
		t.Fatal("mismatched signer accepted")
	}
	if err := Deliver(context.Background(), Config{Auth: AuthMTLS, ClientCertificate: prepared.ClientCertificate},
		nil, nil, nil, io.Discard); err == nil || !strings.Contains(err.Error(), "not yet wired") {
		t.Fatalf("Phase 1 must not fall through into GSSAPI: %v", err)
	}
}

func TestTLSPEMLoadingAndPermissions(t *testing.T) {
	cert := testClientCertificate(t)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key")
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadClientCertificate(certPath, keyPath); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(keyPath, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadClientCertificate(certPath, keyPath); err == nil {
			t.Fatal("group/world-readable key accepted")
		}
	}
	caPath := filepath.Join(dir, "roots.pem")
	for _, invalid := range []string{"", "garbage", "-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")}))} {
		if err := os.WriteFile(caPath, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadServerCAs(caPath); err == nil {
			t.Fatal("invalid root PEM accepted")
		}
	}
}
