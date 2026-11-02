package mail

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func testRSAKey(bits int) *rsa.PublicKey {
	return &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), E: 65537}
}

func TestPublicKeyEquivalentStrength(t *testing.T) {
	for _, tc := range []struct{ size, want int }{
		{512, 0}, {1024, 80}, {2047, 80}, {2048, 112}, {3071, 112},
		{3072, 128}, {4096, 128}, {7680, 192}, {15360, 256},
	} {
		if _, got := publicKeyStrength(testRSAKey(tc.size)); got != tc.want {
			t.Errorf("RSA %d: got %d, want %d", tc.size, got, tc.want)
		}
	}
	for _, tc := range []struct {
		key  any
		want int
	}{
		{&ecdsa.PublicKey{Curve: elliptic.P224()}, 112},
		{&ecdsa.PublicKey{Curve: elliptic.P256()}, 128},
		{&ecdsa.PublicKey{Curve: elliptic.P384()}, 192},
		{&ecdsa.PublicKey{Curve: elliptic.P521()}, 256},
		{ed25519.PublicKey(make([]byte, ed25519.PublicKeySize)), 128},
		{ed25519.PublicKey{}, 0}, {&rsa.PublicKey{}, 0}, {nil, 0},
	} {
		if _, got := publicKeyStrength(tc.key); got != tc.want {
			t.Errorf("key %T: got %d, want %d", tc.key, got, tc.want)
		}
	}
}

func strongTLSState() tls.ConnectionState {
	cert := &x509.Certificate{PublicKey: &ecdsa.PublicKey{Curve: elliptic.P384()},
		SignatureAlgorithm: x509.ECDSAWithSHA384,
		Subject:            pkix.Name{CommonName: "smtp.corp.example"}, NotAfter: time.Now().Add(24 * time.Hour)}
	return tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_256_GCM_SHA384,
		CurveID: tls.CurveP384, PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains: [][]*x509.Certificate{{cert}}}
}

func TestOverallTLSStrengthUsesWeakestObservableComponent(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*tls.ConnectionState)
		want   int
	}{
		{"strong", func(*tls.ConnectionState) {}, 192},
		{"RSA2048", func(s *tls.ConnectionState) { s.PeerCertificates[0].PublicKey = testRSAKey(2048) }, 112},
		{"cipher", func(s *tls.ConnectionState) { s.CipherSuite = tls.TLS_AES_128_GCM_SHA256 }, 128},
		{"exchange", func(s *tls.ConnectionState) { s.CurveID = tls.X25519 }, 128},
		{"hybrid", func(s *tls.ConnectionState) { s.CurveID = tls.X25519MLKEM768 }, 128},
		{"hybridP256", func(s *tls.ConnectionState) { s.CurveID = tls.SecP256r1MLKEM768 }, 128},
		{"hybridP384", func(s *tls.ConnectionState) { s.CurveID = tls.SecP384r1MLKEM1024 }, 192},
		{"unknownExchange", func(s *tls.ConnectionState) { s.CurveID = 0xffff }, 0},
		{"missingExchange", func(s *tls.ConnectionState) { s.CurveID = 0 }, 0},
		{"unknownCipher", func(s *tls.ConnectionState) { s.CipherSuite = 0xffff }, 0},
		{"missingChain", func(s *tls.ConnectionState) { s.VerifiedChains = nil }, 0},
		{"missingCertificate", func(s *tls.ConnectionState) { s.PeerCertificates = nil }, 0},
		{"unknownKey", func(s *tls.ConnectionState) { s.PeerCertificates[0].PublicKey = nil }, 0},
		{"chainKey", func(s *tls.ConnectionState) {
			root := &x509.Certificate{PublicKey: testRSAKey(2048)}
			s.VerifiedChains = [][]*x509.Certificate{{s.PeerCertificates[0], root}}
		}, 112},
		{"chainSignature", func(s *tls.ConnectionState) {
			s.PeerCertificates[0].SignatureAlgorithm = x509.ECDSAWithSHA256
			s.VerifiedChains = [][]*x509.Certificate{{s.PeerCertificates[0], {PublicKey: testRSAKey(15360)}}}
		}, 128},
		{"unknownSignature", func(s *tls.ConnectionState) {
			s.PeerCertificates[0].SignatureAlgorithm = x509.SHA1WithRSA
			s.VerifiedChains = [][]*x509.Certificate{{s.PeerCertificates[0], {PublicKey: testRSAKey(3072)}}}
		}, 0},
		{"trustAnchorSignatureIgnored", func(s *tls.ConnectionState) {
			s.PeerCertificates[0].SignatureAlgorithm = x509.SHA1WithRSA
		}, 192},
		{"RSAKeyTransport", func(s *tls.ConnectionState) {
			s.Version, s.CipherSuite, s.CurveID = tls.VersionTLS12, tls.TLS_RSA_WITH_AES_256_GCM_SHA384, 0
			s.PeerCertificates[0].PublicKey = testRSAKey(2048)
		}, 112},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := strongTLSState()
			tc.change(&state)
			got, reason := overallTLSStrength(state)
			if got != tc.want || (reason != "") != (tc.want == 0) {
				t.Fatalf("got %d (%s), want %d", got, reason, tc.want)
			}
		})
	}
}

func TestTLSDebugDetailsInEmailSnapshot(t *testing.T) {
	state := strongTLSState()
	state.PeerCertificates[0].Subject.CommonName = `<smtp>&.corp.example`
	report := NewTestReport(&bytes.Buffer{}, false)
	report.EnableDebug()
	report.Value("AD domain", "corp.example")
	report.TLS(state)
	data, err := report.TestMessage("self@corp.example", []string{"self@corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	bodies := testmailBodies(t, message)
	for format, body := range bodies {
		for _, want := range []string{"Server TLS certificate / connection", "Certificate key", "ECDSA P-384",
			"Key exchange", state.CurveID.String(), tls.CipherSuiteName(state.CipherSuite), "192-bit classical equivalent"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s missing TLS detail %q:\n%s", format, want, body)
			}
		}
	}
	if strings.Contains(bodies["text/html"], "<smtp>") || !strings.Contains(bodies["text/html"], "&lt;smtp&gt;") {
		t.Fatal("certificate metadata not escaped in HTML")
	}
	report.debug = false
	if strings.Contains(report.renderFormat(reportPlain), "Certificate key") {
		t.Fatal("TLS detail table shown without debug")
	}
}
