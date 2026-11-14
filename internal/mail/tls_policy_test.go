package mail

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func TestServerTrustScopeAndCopy(t *testing.T) {
	if _, err := cloneServerTrust(ServerTrust{Mode: RootsReplace}); err == nil {
		t.Fatal("empty replacement root store accepted")
	}
	if _, err := cloneServerTrust(ServerTrust{ExpiredServerCertificateGrace: -time.Second}); err == nil {
		t.Fatal("negative grace accepted")
	}
	_, err := cloneServerTrust(ServerTrust{ExpiredServerCertificateGrace: time.Hour})
	native := runtime.GOOS == "windows" || runtime.GOOS == "darwin" || runtime.GOOS == "ios"
	if errors.Is(err, ErrTLSFeatureUnavailable) != native || (!native && err != nil) {
		t.Fatalf("native-root grace scope: %v", err)
	}
}

func TestPreparedServerTrustOwnershipAndInvalidation(t *testing.T) {
	for _, change := range []string{"unchanged", "reorder", "remove", "replace", "append", "system", "malformed", "not-ca", "selector"} {
		t.Run(change, func(t *testing.T) {
			input := tlsBenchConfig(t, 0, 2)
			source, err := PrepareAuthentication(input)
			if err != nil {
				t.Fatal(err)
			}
			current := input.WithPreparedTrust(source)
			wantOK := true
			switch change {
			case "reorder":
				current.ServerTrust.Certificates[0], current.ServerTrust.Certificates[1] = current.ServerTrust.Certificates[1], current.ServerTrust.Certificates[0]
			case "remove":
				current.ServerTrust.Certificates = current.ServerTrust.Certificates[:1]
			case "replace":
				cert, _ := tlsBenchCertificate(t, "new-root", true, nil, nil)
				current.ServerTrust.Certificates[0] = cert.Raw
			case "append":
				current.ServerTrust.Mode = RootsAppend
			case "system":
				current.ServerTrust.Mode, current.ServerTrust.Certificates = RootsSystem, nil
			case "malformed":
				current.ServerTrust.Certificates[0] = []byte("bad DER")
				wantOK = false
			case "not-ca":
				cert, _ := tlsBenchCertificate(t, "not-ca", false, nil, nil)
				current.ServerTrust.Certificates[0] = cert.Raw
				wantOK = false
			case "selector":
				current.ServerTrust.Deny[0].Kind = "invalid"
				wantOK = false
			}
			prepared, err := PrepareAuthentication(current)
			if (err == nil) != wantOK {
				t.Fatalf("changed input validation: %v", err)
			}
			if !wantOK {
				return
			}
			if change == "unchanged" && prepared.preparedTrust != source.preparedTrust {
				t.Fatal("unchanged CA input did not reuse immutable material")
			}
			if prepared.ServerTrust.Mode == RootsReplace {
				fresh, err := serverRoots(prepared.ServerTrust)
				if err != nil || !prepared.preparedTrust.replaceRoots.Equal(fresh) {
					t.Fatalf("prepared roots differ from current configured roots: %v", err)
				}
			}
			for _, der := range source.ServerTrust.Certificates {
				der[0] ^= 1
			}
			for _, cert := range source.preparedTrust.certificates {
				if _, err := x509.ParseCertificate(cert.Raw); err != nil {
					t.Fatalf("returned trust mutation corrupted immutable parser bytes: %v", err)
				}
			}
			if _, err := PrepareAuthentication(source); err == nil {
				t.Fatal("mutated returned DER bypassed validation through retained parser data")
			}
		})
	}
}

func TestPreparedTLSVerificationRemainsOperationLocal(t *testing.T) {
	fixture := newCertificateSMTPFixture(t)
	base, err := PrepareAuthentication(Config{Auth: AuthMTLS, ClientCertificate: fixture.client, TLSMode: "implicit",
		ServerTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := x509.ParseCertificate(fixture.server.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{server, fixture.ca},
		VerifiedChains: [][]*x509.Certificate{{server, fixture.ca}}}
	type result struct {
		config   *tls.Config
		evidence *AuthenticationResult
		err      error
	}
	results := make(chan result, 4)
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			call, err := PrepareAuthentication(base)
			if err != nil {
				results <- result{err: err}
				return
			}
			config, evidence, err := authenticationTLS(options{auth: call.Auth, relay: "relay.example.test",
				clientCertificate: call.ClientCertificate, serverTrust: call.ServerTrust, preparedTrust: call.preparedTrust}, io.Discard)
			if err == nil {
				err = config.VerifyConnection(state)
			}
			results <- result{config, evidence, err}
		})
	}
	workers.Wait()
	configs := make(map[*tls.Config]bool)
	evidence := make(map[*AuthenticationResult]bool)
	for range 4 {
		result := <-results
		if result.err != nil || result.config.RootCAs != base.preparedTrust.replaceRoots ||
			!result.evidence.ServerVerification.PolicyPassed || configs[result.config] || evidence[result.evidence] {
			t.Fatalf("shared CA parsing lost operation-local TLS/evidence: %+v", result)
		}
		configs[result.config], evidence[result.evidence] = true, true
	}
	base.ServerTrust.Deny = []CASelector{{Kind: CACertificateSHA256, Digest: sha256.Sum256(fixture.ca.Raw)}}
	denied, err := PrepareAuthentication(base)
	if err != nil {
		t.Fatal(err)
	}
	config, deniedEvidence, err := authenticationTLS(options{auth: denied.Auth, relay: "relay.example.test",
		clientCertificate: denied.ClientCertificate, serverTrust: denied.ServerTrust, preparedTrust: denied.preparedTrust}, io.Discard)
	if err != nil || config.VerifyConnection(state) == nil || deniedEvidence.ServerVerification.PolicyPassed {
		t.Fatalf("prior acceptance bypassed changed CA deny policy: %v", err)
	}
}

func TestPreparedTrustDoesNotCacheSignerOrTimeDecisions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fixture := newCertificateSMTPFixture(t)
		original := fixture.client.PrivateKey.(crypto.Signer)
		signer := &tlsValidationSigner{Signer: original}
		fixture.client.PrivateKey = signer
		base, err := PrepareAuthentication(Config{Auth: AuthMTLS, ClientCertificate: fixture.client, TLSMode: "implicit",
			ServerTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}}})
		if err != nil {
			t.Fatal(err)
		}
		signer.Signer = fixture.caKey
		if _, err := PrepareAuthentication(base); err == nil || !strings.Contains(err.Error(), "does not match") {
			t.Fatalf("CA reuse bypassed changed signer public-key validation: %v", err)
		}
		signer.Signer = original
		config, _, err := authenticationTLS(options{auth: base.Auth, relay: "relay.example.test",
			clientCertificate: base.ClientCertificate, serverTrust: base.ServerTrust, preparedTrust: base.preparedTrust}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		server, err := x509.ParseCertificate(fixture.server.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{server, fixture.ca},
			VerifiedChains: [][]*x509.Certificate{{server, fixture.ca}}}
		if err := config.VerifyConnection(state); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Hour)
		if err := config.VerifyConnection(state); err == nil {
			t.Fatal("previously valid server path remained accepted after expiry")
		}
		if _, err := config.GetClientCertificate(&tls.CertificateRequestInfo{Version: tls.VersionTLS13,
			SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}}); err == nil {
			t.Fatal("previously valid client certificate remained accepted after expiry")
		}
	})
}

func TestServerVerificationNamedExceptions(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name                                            string
		leafEnd, rootEnd                                time.Time
		offset                                          time.Duration
		grace                                           time.Duration
		issuer, untrusted                               bool
		future, wrongName                               bool
		clientOnly, badSignature, critical, constrained bool
		wantOK, wantExpiry, wantIssuer                  bool
	}{
		{name: "strict-valid", wantOK: true},
		{name: "strict-expired", leafEnd: now.Add(-time.Hour)},
		{name: "expiry-inside", leafEnd: now.Add(-time.Hour), grace: 168 * time.Hour, wantOK: true, wantExpiry: true},
		{name: "expiry-exact", leafEnd: now.Add(-168 * time.Hour), grace: 168 * time.Hour, wantOK: true, wantExpiry: true},
		{name: "expiry-outside", leafEnd: now.Add(-168 * time.Hour), offset: time.Nanosecond, grace: 168 * time.Hour},
		{name: "expired-root", rootEnd: now.Add(-time.Hour), leafEnd: now.Add(-time.Hour), grace: 168 * time.Hour},
		{name: "issuer-does-not-waive-expired-root", rootEnd: now.Add(-time.Hour), issuer: true},
		{name: "future-leaf", future: true, grace: 168 * time.Hour, issuer: true},
		{name: "hostname-still-checked", wrongName: true, leafEnd: now.Add(-time.Hour), grace: 168 * time.Hour, issuer: true},
		{name: "eku-still-checked", clientOnly: true, leafEnd: now.Add(-time.Hour), grace: 168 * time.Hour, issuer: true},
		{name: "signature-still-checked", badSignature: true, leafEnd: now.Add(-time.Hour), grace: 168 * time.Hour, issuer: true},
		{name: "critical-still-checked", critical: true, leafEnd: now.Add(-time.Hour), grace: 168 * time.Hour, issuer: true},
		{name: "name-constraints-still-checked", constrained: true, leafEnd: now.Add(-time.Hour), grace: 168 * time.Hour, issuer: true},
		{name: "strict-untrusted", untrusted: true},
		{name: "issuer-only", untrusted: true, issuer: true, wantOK: true, wantIssuer: true},
		{name: "issuer-does-not-waive-expiry", untrusted: true, issuer: true, leafEnd: now.Add(-time.Hour)},
		{name: "combined", untrusted: true, issuer: true, leafEnd: now.Add(-time.Hour), grace: 168 * time.Hour, wantOK: true, wantExpiry: true, wantIssuer: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rootEnd := tt.rootEnd
			if rootEnd.IsZero() {
				rootEnd = now.Add(365 * 24 * time.Hour)
			}
			rootTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Policy root"},
				NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: rootEnd,
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
			}
			if tt.constrained {
				rootTemplate.PermittedDNSDomainsCritical = true
				rootTemplate.PermittedDNSDomains = []string{"other.example.test"}
			}
			root, rootKey := prerequisiteCertificate(t, rootTemplate, nil, nil)
			end := tt.leafEnd
			if end.IsZero() {
				end = now.Add(time.Hour)
			}
			leafTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(2), DNSNames: []string{"relay.example.test"},
				NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: end,
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}
			if tt.future {
				leafTemplate.NotBefore = now.Add(time.Hour)
				leafTemplate.NotAfter = now.Add(2 * time.Hour)
			}
			if tt.clientOnly {
				leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			}
			if tt.critical {
				leafTemplate.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
			}
			leaf, _ := prerequisiteCertificate(t, leafTemplate, root, rootKey)
			if tt.badSignature {
				raw := bytes.Clone(leaf.Raw)
				raw[len(raw)-1] ^= 1
				var err error
				leaf, err = x509.ParseCertificate(raw)
				if err != nil {
					t.Fatal(err)
				}
			}
			roots := x509.NewCertPool()
			if !tt.untrusted {
				roots.AddCert(root)
			}
			host := "relay.example.test"
			if tt.wrongName {
				host = "wrong.example.test"
			}
			policy := ServerTrust{Mode: RootsReplace, ExpiredServerCertificateGrace: tt.grace, InsecureAllowUnverifiableIssuer: tt.issuer}
			originalEnd := leaf.NotAfter
			result, err := verifyServerCertificate([]*x509.Certificate{leaf, root}, roots, policy, host, now.Add(tt.offset))
			if (err == nil) != tt.wantOK {
				t.Fatalf("verification=%+v error=%v wantOK=%v", result, err, tt.wantOK)
			}
			if tt.wantOK && (result.expiryUsed != tt.wantExpiry || result.issuerUsed != tt.wantIssuer) {
				t.Fatalf("exception evidence=%+v", result)
			}
			if !leaf.NotAfter.Equal(originalEnd) {
				t.Fatal("verification mutated original leaf")
			}
		})
	}
}

func TestServerCAPolicyAndRootModes(t *testing.T) {
	now := time.Now().UTC()
	root, key := prerequisiteCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Policy root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, nil)
	leaf, _ := prerequisiteCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"relay.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, root, key)
	input := [][]byte{bytes.Clone(root.Raw)}
	for _, mode := range []RootMode{RootsAppend, RootsReplace} {
		policy, err := cloneServerTrust(ServerTrust{Mode: mode, Certificates: input})
		if err != nil {
			t.Fatal(err)
		}
		policy.Certificates[0][0] ^= 1
		if !bytes.Equal(input[0], root.Raw) {
			t.Fatal("CA input alias")
		}
		policy.Certificates[0][0] ^= 1
		roots, err := serverRoots(policy)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []CASelectorKind{CACertificateSHA256, CASPKISHA256} {
			raw := root.Raw
			if kind == CASPKISHA256 {
				raw = root.RawSubjectPublicKeyInfo
			}
			allowed := CASelector{Kind: kind, Digest: sha256.Sum256(raw)}
			policy.Allow = []CASelector{allowed}
			result, err := verifyServerCertificate([]*x509.Certificate{leaf}, roots, policy, "relay.example.test", now)
			if err != nil || len(result.chain) != 2 {
				t.Fatalf("allowed CA failed: %v", err)
			}
			policy.Deny = []CASelector{allowed}
			if _, err := verifyServerCertificate([]*x509.Certificate{leaf}, roots, policy, "relay.example.test", now); err == nil {
				t.Fatal("allow overrode deny")
			}
			policy.Deny = nil
			policy.Allow[0].Digest[0] ^= 1
			if _, err := verifyServerCertificate([]*x509.Certificate{leaf}, roots, policy, "relay.example.test", now); err == nil {
				t.Fatal("unmatched allow-list accepted")
			}
		}
	}
}
