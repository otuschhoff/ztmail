package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestTransportExceptionsAndPermissiveClientPolicy(t *testing.T) {
	for _, mode := range []string{"configured-unused", "expired-used", "issuer-used", "both-used", "permissive-client"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newCertificateSMTPFixture(t)
			policy := ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}}
			if mode == "expired-used" || mode == "both-used" {
				cert, key := prerequisiteCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(20), DNSNames: []string{"relay.example.test"},
					NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(-time.Hour),
					KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
					fixture.ca, fixture.caKey)
				fixture.server.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw, fixture.ca.Raw}, PrivateKey: key}}
				policy.ExpiredServerCertificateGrace = 168 * time.Hour
			}
			if mode == "issuer-used" || mode == "both-used" {
				policy.Certificates = [][]byte{newCertificateSMTPFixture(t).ca.Raw}
				policy.InsecureAllowUnverifiableIssuer = true
			}
			if mode == "configured-unused" {
				policy.ExpiredServerCertificateGrace = 168 * time.Hour
				policy.InsecureAllowUnverifiableIssuer = true
			}
			if mode == "permissive-client" {
				fixture.server.ClientAuth = tls.RequestClientCert
				fixture.server.ClientCAs = nil
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			wire := make(chan smtpResult, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					wire <- smtpResult{err: err}
					return
				}
				wire <- serveCertificateSMTP(conn, fixture, true, true, false)
			}()
			report := NewTestReport(io.Discard, false)
			var auth AuthenticationResult
			var warnings []error
			err = Deliver(context.Background(), Config{Relay: "relay.example.test", Hello: "host.example.test", TLSMode: "implicit",
				Port: listener.Addr().(*net.TCPAddr).Port, Timeout: 3 * time.Second, Auth: AuthMTLS,
				ClientCertificate: fixture.client, ServerTrust: policy, Report: report, Test: true,
				Authentication: func(result AuthenticationResult) { auth = result },
				Warning:        func(err error) { warnings = append(warnings, err) }},
				nil, nil, certificateResolver{netip.MustParseAddr("127.0.0.1")}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			assertNoEmailCommands(t, <-wire)
			minimumWarnings := 1
			if mode != "permissive-client" {
				minimumWarnings++
			}
			if mode == "expired-used" || mode == "issuer-used" || mode == "both-used" {
				minimumWarnings++
			}
			if len(warnings) != minimumWarnings {
				t.Fatalf("configured/used/authorization warnings not surfaced to library callback: %v", warnings)
			}
			verification := auth.ServerVerification
			expiryUsed := mode == "expired-used" || mode == "both-used"
			issuerUsed := mode == "issuer-used" || mode == "both-used"
			if !auth.ClientCertificatePresented || auth.SMTPAuthConfirmed || !verification.PolicyPassed ||
				verification.ExpiryExceptionUsed != expiryUsed || verification.IssuerExceptionUsed != issuerUsed ||
				verification.Trusted == issuerUsed || (expiryUsed && verification.ExpiredLeafAge < time.Hour) {
				t.Fatalf("actual exception/presentation evidence incorrect: %+v", auth)
			}
			if got := strings.HasPrefix(report.values["Transport security"], "WARNING:"); got != (expiryUsed || issuerUsed) {
				t.Fatalf("transport misrepresents actually used exceptions: %s", report.values["Transport security"])
			}
			if mode == "configured-unused" && !strings.Contains(report.renderIssues(reportPlain), "explicit insecure server TLS options") {
				t.Fatal("configured but unused exception lost warning")
			}
			if mode == "permissive-client" && !strings.Contains(report.values["Authentication"], "not independently confirmed") {
				t.Fatal("permissive relay policy was upgraded to authorization evidence")
			}
			raw, err := report.jsonSnapshot()
			if err != nil || bytes.Contains(raw, []byte("PRIVATE KEY")) {
				t.Fatalf("unsafe or unavailable raw evidence: %v", err)
			}
		})
	}
}
