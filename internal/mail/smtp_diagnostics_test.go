package mail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func assertNoEmailCommands(t *testing.T, result smtpResult) {
	t.Helper()
	if result.message != "" {
		t.Fatal("test mode transmitted message content")
	}
	for _, command := range result.commands {
		for _, forbidden := range []string{"MAIL FROM:", "RCPT TO:", "DATA"} {
			if strings.HasPrefix(command, forbidden) {
				t.Fatalf("test mode issued %q", command)
			}
		}
	}
}

func TestSMTPFinalAuthFailureIsNotReportedAsQuitFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	results := make(chan smtpResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- smtpResult{err: err}
			return
		}
		results <- serveSMTPAuthReply(conn, false, false, nil, "535 5.7.8 Authentication rejected")
	}()
	var output bytes.Buffer
	o := options{testMode: true, report: NewTestReport(&output, true), relay: "relay.example.test",
		port: listener.Addr().(*net.TCPAddr).Port, hello: "host.example.test", tlsMode: "off", timeout: 3 * time.Second}
	security := &fakeSecurity{offer: []byte{1, 0, 0, 0}}
	backend := &fakeBackend{security: security, address: netip.MustParseAddr("127.0.0.1")}
	err = deliver(context.Background(), o, nil, nil, backend, &output)
	result := <-results
	assertNoEmailCommands(t, result)
	if err == nil || !strings.Contains(err.Error(), "SMTP AUTH GSSAPI") || !strings.Contains(err.Error(), "535") {
		t.Fatalf("final AUTH refusal incorrectly attributed: %v", err)
	}
	if result.err != nil || security.closed != 1 {
		t.Fatalf("server=%v security closed=%d", result.err, security.closed)
	}
	if strings.Contains(output.String(), "[OK] SMTP AUTH GSSAPI") || strings.Contains(output.String(), "SMTP QUIT") ||
		!strings.Contains(output.String(), "[OK] GSSAPI SASL negotiation") ||
		!strings.Contains(output.String(), "[FAIL] SMTP AUTH GSSAPI") {
		t.Fatalf("incorrect authentication report: %s", &output)
	}
	foundEmpty := false
	for _, command := range result.commands {
		if command == "" {
			foundEmpty = true
		}
	}
	if !foundEmpty {
		t.Fatal("nil context token did not produce an empty SMTP continuation")
	}
}

func TestSMTPTestAuthenticatesWithoutSendingEmail(t *testing.T) {
	for _, mode := range []string{"success", "auth-failure", "quit-failure", "cleanup-failure", "starttls-missing"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			results := make(chan smtpResult, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					results <- smtpResult{err: err}
					return
				}
				results <- serveSMTP(conn, false, mode == "quit-failure")
			}()
			port := listener.Addr().(*net.TCPAddr).Port
			var output bytes.Buffer
			o := options{testMode: true, report: NewTestReport(&output, true), relay: "relay.corp.example", port: port,
				hello: "host.corp.example", spn: "smtp/relay.corp.example", tlsMode: "off", timeout: 3 * time.Second}
			if mode == "starttls-missing" {
				o.tlsMode = "required"
			}
			security := &fakeSecurity{offer: []byte{1, 0, 0, 0}, fail: mode == "auth-failure"}
			cleanupErr := errors.New("synthetic cleanup failure")
			if mode == "cleanup-failure" {
				security.closeErr = cleanupErr
			}
			backend := &fakeBackend{security: security, address: netip.MustParseAddr("127.0.0.1")}
			err = deliver(context.Background(), o, []string{"must-not-send@corp.example"}, []byte("must-not-send"), backend, &output)
			result := <-results
			assertNoEmailCommands(t, result)
			if mode == "success" {
				if err != nil || result.err != nil {
					t.Fatalf("client=%v server=%v", err, result.err)
				}
				for _, expected := range []string{"[OK] Relay DNS lookup", "[OK] SMTP TCP connection", "[OK] SMTP greeting",
					"[OK] SMTP EHLO", "[OK] GSSAPI mutual authentication", "[OK] GSSAPI SASL negotiation",
					"[OK] SMTP AUTH GSSAPI", "[OK] SMTP QUIT", "[OK] GSSAPI cleanup"} {
					if !strings.Contains(output.String(), expected) {
						t.Fatalf("missing %q in %s", expected, &output)
					}
				}
				if result.commands[len(result.commands)-1] != "QUIT" {
					t.Fatal("test did not disconnect after authentication")
				}
			} else if err == nil {
				t.Fatal("failed test stage returned success")
			}
			if mode == "cleanup-failure" && !errors.Is(err, cleanupErr) {
				t.Fatalf("lost cleanup error: %v", err)
			}
			if mode == "starttls-missing" {
				if backend.contexts != 0 {
					t.Fatal("created GSSAPI context without required TLS")
				}
			} else if security.closed != 1 || backend.contexts != 1 {
				t.Fatal("incorrect security context lifecycle")
			}
			if strings.Contains(output.String(), "message accepted") {
				t.Fatal("test mode emitted send-success wording")
			}
		})
	}
}

func TestSMTPTestTLS(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}}}
	for _, mode := range []string{"required", "implicit", "untrusted"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			results := make(chan smtpResult, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					results <- smtpResult{err: err}
					return
				}
				if mode == "implicit" || mode == "untrusted" {
					results <- serveSMTP(tls.Server(conn, tlsConfig), false, false)
				} else {
					results <- serveSMTPWithTLS(conn, false, false, tlsConfig)
				}
			}()
			// Isolate test trust roots rather than changing the parent process's TLS policy.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSMTPTestTLSHelper$")
			cmd.Env = append(os.Environ(), "ZTMAIL_TEST_TLS_MODE="+mode, "ZTMAIL_TEST_TLS_CA="+certPath,
				fmt.Sprintf("ZTMAIL_TEST_TLS_PORT=%d", listener.Addr().(*net.TCPAddr).Port))
			output, err := cmd.CombinedOutput()
			listener.Close()
			result := <-results
			if err != nil {
				t.Fatalf("TLS test helper failed: %v\n%s", err, output)
			}
			assertNoEmailCommands(t, result)
			if mode != "untrusted" {
				if result.err != nil || !strings.Contains(string(output), "[OK] SMTP AUTH GSSAPI") {
					t.Fatalf("TLS authentication failed: %v\n%s", result.err, output)
				}
				hellos := 0
				for _, command := range result.commands {
					if strings.HasPrefix(command, "EHLO ") {
						hellos++
					}
				}
				if mode == "required" && hellos != 2 {
					t.Fatalf("expected pre/post-TLS EHLO, got %d", hellos)
				}
			} else {
				for _, command := range result.commands {
					if strings.HasPrefix(command, "AUTH ") {
						t.Fatal("authenticated before certificate verification")
					}
				}
			}
		})
	}
}

func TestSMTPTestTLSHelper(t *testing.T) {
	mode := os.Getenv("ZTMAIL_TEST_TLS_MODE")
	if mode == "" {
		t.Skip("subprocess TLS helper")
	}
	roots := x509.NewCertPool()
	cert, err := os.ReadFile(os.Getenv("ZTMAIL_TEST_TLS_CA"))
	if err != nil {
		t.Fatal(err)
	}
	if mode != "untrusted" && !roots.AppendCertsFromPEM(cert) {
		t.Fatal("invalid test CA")
	}
	t.Setenv("GODEBUG", "x509usefallbackroots=1")
	x509.SetFallbackRoots(roots)
	port, err := strconv.Atoi(os.Getenv("ZTMAIL_TEST_TLS_PORT"))
	if err != nil {
		t.Fatal(err)
	}
	tlsMode := mode
	if mode == "untrusted" {
		tlsMode = "implicit"
	}
	report := NewTestReport(os.Stdout, true)
	o := options{testMode: true, report: report, relay: "localhost", hello: "host.corp.example", spn: "smtp/localhost",
		port: port, tlsMode: tlsMode, timeout: 3 * time.Second}
	backend := &fakeBackend{security: &fakeSecurity{offer: []byte{1, 0, 0, 0}}, address: netip.MustParseAddr("127.0.0.1")}
	err = deliver(context.Background(), o, nil, nil, backend, os.Stdout)
	if mode == "untrusted" {
		if err == nil || backend.contexts != 0 {
			t.Fatalf("untrusted TLS accepted: %v", err)
		}
		return
	}
	if err != nil || backend.state == nil || len(backend.state.VerifiedChains) == 0 {
		t.Fatalf("verified TLS state not passed to GSSAPI: %v", err)
	}
	if value := report.values["Transport security"]; !strings.HasPrefix(value, "OK ("+tlsConnectionDetails(*backend.state)+"; CN=localhost; ") ||
		!strings.HasSuffix(value, " left)") {
		t.Fatalf("missing verified certificate CN/expiry: %q", value)
	}
}

func TestCertificateLifetime(t *testing.T) {
	now := time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		remaining time.Duration
		want      string
	}{
		{69 * 24 * time.Hour, "69 days left"},
		{48*time.Hour - time.Second, "1 day left"},
		{24 * time.Hour, "1 day left"},
		{24*time.Hour - time.Second, "23 hours left"},
		{time.Hour, "1 hour left"},
		{time.Hour - time.Second, "59 minutes left"},
		{time.Minute, "1 minute left"},
		{time.Second, "less than 1 minute left"},
		{0, "expired"},
		{-time.Second, "expired"},
	} {
		if got := certificateLifetime(now.Add(tc.remaining), now); got != tc.want {
			t.Errorf("remaining %s: got %q, want %q", tc.remaining, got, tc.want)
		}
	}
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: "smtp.corp.example"}, NotAfter: now.Add(69 * 24 * time.Hour)}
	state := tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{leaf, {NotAfter: now.Add(365 * 24 * time.Hour)}}}
	if got := tlsTransportSummary(state, now); got != "OK (TLS1.3 AES-128-GCM; CN=smtp.corp.example; 69 days left)" {
		t.Fatalf("wrong leaf certificate summary: %s", got)
	}
	leaf.Subject.CommonName = ""
	if got := tlsTransportSummary(state, now); got != "OK (TLS1.3 AES-128-GCM; CN unavailable; 69 days left)" {
		t.Fatalf("wrong missing-CN summary: %s", got)
	}
	if got := tlsTransportSummary(tls.ConnectionState{}, now); got != "OK (TLS unavailable cipher unavailable; CN unavailable; expiry unavailable)" {
		t.Fatalf("wrong missing-certificate summary: %s", got)
	}

}

func TestTLSConnectionDetails(t *testing.T) {
	for _, tc := range []struct {
		version, cipher uint16
		want            string
	}{
		{tls.VersionTLS13, tls.TLS_AES_128_GCM_SHA256, "TLS1.3 AES-128-GCM"},
		{tls.VersionTLS13, tls.TLS_AES_256_GCM_SHA384, "TLS1.3 AES-256-GCM"},
		{tls.VersionTLS13, tls.TLS_CHACHA20_POLY1305_SHA256, "TLS1.3 ChaCha20-256"},
		{tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "TLS1.2 AES-128-GCM"},
		{tls.VersionTLS12, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "TLS1.2 AES-256-GCM"},
		{tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS1.2 AES-128-CBC"},
		{tls.VersionTLS12, 0xffff, "TLS1.2 0xFFFF"},
	} {
		if got := tlsConnectionDetails(tls.ConnectionState{Version: tc.version, CipherSuite: tc.cipher}); got != tc.want {
			t.Errorf("version=%x cipher=%x: got %q, want %q", tc.version, tc.cipher, got, tc.want)
		}
	}
}
