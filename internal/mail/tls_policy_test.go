package mail

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"runtime"
	"testing"
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
