package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	netmail "net/mail"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCertificateTestmailEvidenceSnapshot(t *testing.T) {
	for _, method := range []AuthMode{AuthMTLS, AuthMTLSExternal} {
		t.Run(string(method), func(t *testing.T) {
			fixture := newCertificateSMTPFixture(t)
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
			report.EnableDebug()
			report.EnableTestMail()
			err = Deliver(context.Background(), Config{Relay: "relay.example.test", Hello: "host.example.test",
				Port: listener.Addr().(*net.TCPAddr).Port, Timeout: 3 * time.Second, TLSMode: "implicit",
				Auth: method, ClientCertificate: fixture.client, ServerTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}},
				From: "sender@example.test", TestMail: true, Report: report},
				[]string{"recipient@example.test"}, nil, certificateResolver{netip.MustParseAddr("127.0.0.1")}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			peer := <-wire
			if peer.err != nil {
				t.Fatal(peer.err)
			}
			message, err := netmail.ReadMessage(strings.NewReader(peer.message))
			if err != nil {
				t.Fatal(err)
			}
			bodies, rawJSON := testmailContents(t, message)
			var snapshot jsonTestReport
			if err := json.Unmarshal(rawJSON, &snapshot); err != nil {
				t.Fatal(err)
			}
			auth := snapshot.Authentication
			if snapshot.SchemaVersion != 2 || snapshot.SnapshotPhase != "after_transport_authentication_before_data" ||
				auth.Method != method || !auth.TLSEstablished || !auth.ClientCertificatePresented ||
				!auth.ClientCertificateRequested || auth.SMTPAuthConfirmed != (method == AuthMTLSExternal) ||
				auth.ClientCertificate == nil || !auth.ServerVerification.PolicyPassed || !auth.ServerVerification.Trusted {
				t.Fatalf("snapshot lacks actual pre-DATA evidence: %+v", snapshot)
			}
			for _, body := range bodies {
				for _, expected := range []string{"Client certificate", "Not applicable", "client_certificate_local", "no SMTP AUTH confirmation"} {
					if !strings.Contains(body, expected) {
						t.Errorf("missing %q in %s report", expected, method)
					}
				}
				if strings.Contains(body, "Kerberos ticket strength") || strings.Contains(body, "-----BEGIN") {
					t.Fatal("mTLS report invented Kerberos strength or exposed certificate material")
				}
			}
			for _, token := range []string{"\x1b[", "<code", "<span", "PRIVATE KEY", "accepted;"} {
				if bytes.Contains(rawJSON, []byte(token)) {
					t.Fatalf("JSON contains styling/private material/post-DATA result %q", token)
				}
			}
			if !strings.Contains(bodies["text/html"], "<code") ||
				!strings.Contains(bodies["text/plain"], "not proof of relay-side certificate verification") {
				t.Fatal("lost technical styling or client evidence provenance")
			}
		})
	}
}

func TestCertificateReportTrustExceptionsAndEscaping(t *testing.T) {
	for _, issuerException := range []bool{false, true} {
		report := NewTestReport(io.Discard, false)
		report.AuthenticationMethod(AuthMTLS)
		report.EnableDebug()
		report.color = true
		now := time.Now().UTC()
		report.snapshotAt = now
		cert := CertificateInfo{Subject: `CN=<unsafe&client>`, Issuer: "CN=Issuer", SHA256: "safe-fingerprint",
			NotBefore: now.Add(-4 * time.Second), NotAfter: now.Add(72 * time.Hour),
			PublicKey: "ECDSA P-256 (256-bit)", ClassicalKeyStrength: 128}
		report.authenticationResult(AuthenticationResult{Method: AuthMTLS, TLSEstablished: true,
			ClientCertificateRequested: true, ClientCertificatePresented: true, ClientCertificate: &cert,
			ServerVerification: ServerVerificationInfo{RootMode: RootsReplace, AnchorSHA256: "anchor",
				Trusted: !issuerException, PolicyPassed: true, AllowConfigured: true, DenyConfigured: true,
				ExpiryGrace: 168 * time.Hour, ExpiryExceptionUsed: true,
				IssuerExceptionConfigured: issuerException, IssuerExceptionUsed: issuerException}})
		cert.Subject = "must not alias report"
		html := report.renderFormat(reportHTML)
		plain := report.renderFormat(reportPlain)
		terminal := report.renderFormat(reportTerminal)
		for _, expected := range []string{"not strict verification", "not independently confirmed", "client_certificate_local"} {
			if !strings.Contains(plain, expected) || !strings.Contains(html, expected) {
				t.Fatalf("surfaces disagree about exception/authentication: missing %q", expected)
			}
			if !strings.Contains(terminal, "WARNING:") || !strings.Contains(terminal, "no SMTP AUTH") ||
				!strings.Contains(terminal, "client_certificate_local") {
				t.Fatal("terminal omitted method/trust/provenance evidence")
			}
		}
		if !strings.Contains(html, "&lt;unsafe&amp;client&gt;") || strings.Contains(html, "<unsafe&client>") ||
			strings.Contains(html, "must not alias report") || !strings.Contains(html, "color:#a16207") {
			t.Fatal("lost escaped monospace identity, warning colour, or independent metadata ownership")
		}
		if issuerException && (!strings.Contains(plain, "untrusted anchor (not issuer-verified)") ||
			strings.Contains(plain, "Policy passed; trusted issuer")) {
			t.Fatal("issuer exception was mislabelled as trusted verification")
		}
		if !strings.Contains(plain, "Age: new") || !strings.Contains(plain, "Start (UTC): now") ||
			strings.Contains(plain, "\x1b[") || strings.Contains(plain, "<code") {
			t.Fatal("client validity bypassed shared fresh-age/raw-output policy")
		}
	}
}
