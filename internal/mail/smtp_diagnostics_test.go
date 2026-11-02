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
			o := options{testMode: true, report: NewTestReport(&output), relay: "relay.corp.example", port: port,
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
	report := NewTestReport(os.Stdout)
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
}
