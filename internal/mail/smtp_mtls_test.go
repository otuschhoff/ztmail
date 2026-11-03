package mail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

type certificateResolver struct {
	address netip.Addr
}

func (r certificateResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{r.address}, nil
}

type certificateSMTPFixture struct {
	client *tls.Certificate
	ca     *x509.Certificate
	server *tls.Config
}

func newCertificateSMTPFixture(t *testing.T) certificateSMTPFixture {
	t.Helper()
	now := time.Now()
	ca, key := prerequisiteCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "SMTP fixture CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, nil)
	server, serverKey := prerequisiteCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"relay.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, key)
	client, clientKey := prerequisiteCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "SMTP fixture client"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca, key)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return certificateSMTPFixture{
		client: &tls.Certificate{Certificate: [][]byte{client.Raw}, PrivateKey: clientKey, Leaf: client},
		ca:     ca,
		server: &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
			Certificates: []tls.Certificate{{Certificate: [][]byte{server.Raw, ca.Raw}, PrivateKey: serverKey}}},
	}
}

func serveCertificateSMTP(conn net.Conn, fixture certificateSMTPFixture, implicit, external, rejectAuth bool) (result smtpResult) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		result.err = err
		return
	}
	if implicit {
		secure := tls.Server(conn, fixture.server)
		if err := secure.Handshake(); err != nil {
			result.err = err
			return
		}
		conn = secure
	}
	reader := bufio.NewReader(conn)
	reply := func(value string) bool {
		_, result.err = fmt.Fprintf(conn, "%s\r\n", value)
		return result.err == nil
	}
	if !reply("220 relay.example.test") {
		return
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			result.err = err
			return
		}
		command := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		result.commands = append(result.commands, command)
		switch {
		case strings.HasPrefix(command, "EHLO "):
			capabilities := "250-relay.example.test\r\n"
			if !implicit {
				capabilities += "250-STARTTLS\r\n"
			}
			if external {
				capabilities += "250-AUTH EXTERNAL\r\n"
			}
			if !reply(capabilities + "250 SIZE 1048576") {
				return
			}
		case command == "STARTTLS":
			if !reply("220 begin TLS") {
				return
			}
			secure := tls.Server(conn, fixture.server)
			if err := secure.Handshake(); err != nil {
				result.err = err
				return
			}
			conn, reader, implicit = secure, bufio.NewReader(secure), true
		case command == "AUTH EXTERNAL =":
			response := "235 2.7.0 OK"
			if rejectAuth {
				response = "535 5.7.8 rejected"
			}
			if !reply(response) {
				return
			}
		case strings.HasPrefix(command, "MAIL FROM:"), strings.HasPrefix(command, "RCPT TO:"):
			if !reply("250 OK") {
				return
			}
		case command == "DATA":
			if !reply("354 send content") {
				return
			}
			data, err := io.ReadAll(textproto.NewReader(reader).DotReader())
			result.message, result.err = string(data), err
			if err != nil || !reply("250 accepted") {
				return
			}
		case command == "QUIT":
			reply("221 bye")
			return
		default:
			result.err = fmt.Errorf("unexpected certificate SMTP command %q", command)
			return
		}
	}
}

func TestCertificateSMTPModesAndRejections(t *testing.T) {
	for _, mode := range []string{"required", "implicit"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			for _, method := range []AuthMode{AuthMTLS, AuthMTLSExternal} {
				t.Run(fmt.Sprintf("%s/%x/%s", mode, version, method), func(t *testing.T) {
					fixture := newCertificateSMTPFixture(t)
					fixture.server.MinVersion, fixture.server.MaxVersion = version, version
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
						results <- serveCertificateSMTP(conn, fixture, mode == "implicit", true, false)
					}()
					var output bytes.Buffer
					var auth AuthenticationResult
					config := Config{Relay: "relay.example.test", Hello: "host.example.test", Port: listener.Addr().(*net.TCPAddr).Port,
						Timeout: 3 * time.Second, TLSMode: mode, Auth: method, ClientCertificate: fixture.client,
						ServerTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}},
						Test:        true, Report: NewTestReport(&output, true), Authentication: func(result AuthenticationResult) { auth = result }}
					err = Deliver(context.Background(), config, nil, nil, certificateResolver{netip.MustParseAddr("127.0.0.1")}, &output)
					if err != nil {
						t.Fatal(err)
					}
					result := <-results
					assertNoEmailCommands(t, result)
					if result.err != nil || !auth.ClientCertificatePresented || !auth.ClientCertificateRequested ||
						auth.SMTPAuthConfirmed != (method == AuthMTLSExternal) || !auth.ServerVerification.Trusted {
						t.Fatalf("auth=%+v server=%v", auth, result.err)
					}
					for _, command := range result.commands {
						if strings.Contains(command, "GSSAPI") || (method == AuthMTLS && strings.HasPrefix(command, "AUTH ")) {
							t.Fatalf("unexpected authentication fallback: %v", result.commands)
						}
					}
				})
			}
		}
	}
	for _, failure := range []string{"no-request", "untrusted-client", "auth-reject", "missing-external", "wrong-host", "denied-ca"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newCertificateSMTPFixture(t)
			if failure == "no-request" {
				fixture.server.ClientAuth = tls.NoClientCert
			}
			if failure == "untrusted-client" {
				fixture.client = testClientCertificate(t)
			}
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
				results <- serveCertificateSMTP(conn, fixture, true, failure != "missing-external", failure == "auth-reject")
			}()
			config := Config{Relay: "relay.example.test", Hello: "host.example.test", Port: listener.Addr().(*net.TCPAddr).Port,
				Timeout: 3 * time.Second, TLSMode: "implicit", Auth: AuthMTLSExternal, ClientCertificate: fixture.client,
				ServerTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}}, From: "sender@example.test"}
			if failure == "wrong-host" {
				config.Relay = "wrong.example.test"
			}
			if failure == "denied-ca" {
				selector, err := ParseCASelector(CACertificateSHA256, certificateInfo(fixture.ca).SHA256)
				if err != nil {
					t.Fatal(err)
				}
				config.ServerTrust.Deny = []CASelector{selector}
			}
			err = Deliver(context.Background(), config, []string{"recipient@example.test"}, []byte("Subject: Test\r\n\r\nBody\r\n"),
				certificateResolver{netip.MustParseAddr("127.0.0.1")}, io.Discard)
			if err == nil || errors.Is(err, ErrDeliveryUncertain) {
				t.Fatalf("certificate failure must be certain before DATA: %v", err)
			}
			assertNoEmailCommands(t, <-results)
		})
	}
}
