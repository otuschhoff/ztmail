package mail

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCAPolicyAlternatePathsAndRenewal(t *testing.T) {
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root A"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	a, aKey := prerequisiteCertificate(t, template, nil, nil)
	template.SerialNumber, template.Subject.CommonName = big.NewInt(2), "Root B"
	b, bKey := prerequisiteCertificate(t, template, nil, nil)
	template.SerialNumber, template.Subject.CommonName = big.NewInt(3), "Intermediate"
	intermediateA, intermediateKey := prerequisiteCertificate(t, template, a, aKey)
	template.SerialNumber = big.NewInt(4)
	raw, err := x509.CreateCertificate(rand.Reader, template, b, &intermediateKey.PublicKey, bKey)
	if err != nil {
		t.Fatal(err)
	}
	intermediateB, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := prerequisiteCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(5),
		DNSNames: []string{"relay.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, intermediateA, intermediateKey)
	roots := x509.NewCertPool()
	roots.AddCert(a)
	roots.AddCert(b)
	certSelector := func(cert *x509.Certificate) CASelector {
		return CASelector{Kind: CACertificateSHA256, Digest: sha256.Sum256(cert.Raw)}
	}
	peer := []*x509.Certificate{leaf, intermediateA, intermediateB, a, b}
	policy := ServerTrust{Allow: []CASelector{certSelector(b)}, Deny: []CASelector{certSelector(a), certSelector(intermediateA)}}
	result, err := verifyServerCertificate(peer, roots, policy, "relay.example.test", now)
	if err != nil || len(result.chain) != 3 || !result.chain[2].Equal(b) || !result.chain[1].Equal(intermediateB) {
		t.Fatalf("rejected alternate must not hide valid allowed path: %+v %v", result, err)
	}
	policy.Deny = append(policy.Deny, CASelector{Kind: CASPKISHA256, Digest: sha256.Sum256(intermediateA.RawSubjectPublicKeyInfo)})
	if _, err := verifyServerCertificate(peer, roots, policy, "relay.example.test", now); err == nil {
		t.Fatal("shared intermediate SPKI deny did not reject both paths")
	}
	if _, err := acceptableServerChain(nil, policy, now); err == nil {
		t.Fatal("missing chain evidence accepted")
	}
	template.SerialNumber, template.Subject = big.NewInt(6), b.Subject
	renewedDER, err := x509.CreateCertificate(rand.Reader, template, template, &bKey.PublicKey, bKey)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := x509.ParseCertificate(renewedDER)
	if err != nil {
		t.Fatal(err)
	}
	renewedRoots := x509.NewCertPool()
	renewedRoots.AddCert(renewed)
	policy = ServerTrust{Allow: []CASelector{{Kind: CASPKISHA256, Digest: sha256.Sum256(b.RawSubjectPublicKeyInfo)}}}
	if _, err := verifyServerCertificate([]*x509.Certificate{leaf, intermediateB}, renewedRoots, policy, "relay.example.test", now); err != nil {
		t.Fatalf("renewal under allowed same SPKI failed: %v", err)
	}
	policy.Allow = []CASelector{certSelector(b)}
	if _, err := verifyServerCertificate([]*x509.Certificate{leaf, intermediateB}, renewedRoots, policy, "relay.example.test", now); err == nil {
		t.Fatal("old certificate digest allowed a renewed certificate")
	}
}

func TestIssuerExceptionSuppliedPathAndPolicy(t *testing.T) {
	now := time.Now()
	root, rootKey := prerequisiteCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Untrusted root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, nil)
	leaf, _ := prerequisiteCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"relay.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, root, rootKey)
	self, _ := prerequisiteCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Self signed"},
		DNSNames: []string{"relay.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, nil, nil)
	unrelated, _ := prerequisiteCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "Unrelated CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, nil)
	for _, tt := range []struct {
		name string
		peer []*x509.Certificate
		deny []CASelector
		ok   bool
	}{
		{"missing-issuer", []*x509.Certificate{leaf}, nil, false},
		{"supplied-anchor", []*x509.Certificate{leaf, root}, nil, true},
		{"self-signed-valid", []*x509.Certificate{self}, nil, true},
		{"deny-under-exception", []*x509.Certificate{leaf, root}, []CASelector{{Kind: CACertificateSHA256, Digest: sha256.Sum256(root.Raw)}}, false},
		{"irrelevant-denied-peer", []*x509.Certificate{leaf, root, unrelated}, []CASelector{{Kind: CACertificateSHA256, Digest: sha256.Sum256(unrelated.Raw)}}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := verifyServerCertificate(tt.peer, x509.NewCertPool(), ServerTrust{InsecureAllowUnverifiableIssuer: true, Deny: tt.deny},
				"relay.example.test", now)
			if (err == nil) != tt.ok || (tt.ok && !result.issuerUsed) {
				t.Fatalf("supplied path/policy result=%+v err=%v", result, err)
			}
		})
	}
	forged := bytes.Clone(self.Raw)
	forged[len(forged)-1] ^= 1
	invalid, err := x509.ParseCertificate(forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyServerCertificate([]*x509.Certificate{invalid}, x509.NewCertPool(),
		ServerTrust{InsecureAllowUnverifiableIssuer: true}, "relay.example.test", now); err == nil {
		t.Fatal("forged self-signed leaf became its own unchecked anchor")
	}
}

func TestCASelectorNormalizationAndFailures(t *testing.T) {
	raw := strings.Repeat("AB:", 31) + "AB"
	selector, err := ParseCASelector(CASPKISHA256, raw)
	var expected [sha256.Size]byte
	for i := range expected {
		expected[i] = 0xab
	}
	if err != nil || selector.Digest != expected {
		t.Fatalf("colon/case digest normalization: %+v %v", selector, err)
	}
	for _, value := range []string{"", "aa", strings.Repeat("a", 63), strings.Repeat("zz", 32)} {
		if _, err := ParseCASelector(CACertificateSHA256, value); err == nil {
			t.Fatalf("malformed selector accepted: %q", value)
		}
	}
	if _, err := ParseCASelector("subject", strings.Repeat("ab", 32)); err == nil {
		t.Fatal("unsupported selector accepted")
	}
}

func TestCAKeyUsageOptionalButRestrictiveUsageEnforced(t *testing.T) {
	for _, usage := range []x509.KeyUsage{0, x509.KeyUsageCertSign, x509.KeyUsageDigitalSignature} {
		root, key := prerequisiteCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(1),
			Subject: pkix.Name{CommonName: "Optional key usage CA"}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: usage}, nil, nil)
		_, err := cloneServerTrust(ServerTrust{Mode: RootsReplace, Certificates: [][]byte{root.Raw}})
		wantOK := usage != x509.KeyUsageDigitalSignature
		if (err == nil) != wantOK {
			t.Fatalf("CA key usage %v validation: %v", usage, err)
		}
		leaf, _ := prerequisiteCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"relay.example.test"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}, root, key)
		_, err = verifyServerCertificate([]*x509.Certificate{leaf, root}, x509.NewCertPool(),
			ServerTrust{InsecureAllowUnverifiableIssuer: true}, "relay.example.test", time.Now())
		if (err == nil) != wantOK {
			t.Fatalf("provisional CA key usage %v verification: %v", usage, err)
		}
	}
}

func TestSystemAppendReplaceRootIsolation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("deterministic system-store injection uses Linux SSL_CERT_FILE/SSL_CERT_DIR; native stores are operator checks")
	}
	if directory := os.Getenv("ZTMAIL_TEST_SYSTEM_ROOT_DIR"); directory != "" {
		systemPEM, err := os.ReadFile(filepath.Join(directory, "system.pem"))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(systemPEM)
		system, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		custom, err := LoadServerCAs(filepath.Join(directory, "custom.pem"))
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []RootMode{RootsSystem, RootsAppend, RootsReplace} {
			policy := ServerTrust{Mode: mode}
			if mode != RootsSystem {
				policy.Certificates = custom
			}
			roots, err := serverRoots(policy)
			if err != nil {
				t.Fatal(err)
			}
			_, err = system.Verify(x509.VerifyOptions{Roots: roots})
			if (err == nil) != (mode != RootsReplace) {
				t.Fatalf("%s silently changed system trust: %v", mode, err)
			}
			customCA, err := x509.ParseCertificate(custom[0])
			if err != nil {
				t.Fatal(err)
			}
			_, err = customCA.Verify(x509.VerifyOptions{Roots: roots})
			if (err == nil) != (mode != RootsSystem) {
				t.Fatalf("%s custom trust mismatch: %v", mode, err)
			}
		}
		return
	}
	directory := t.TempDir()
	for i, name := range []string{"system", "custom"} {
		cert, _ := prerequisiteCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)),
			Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, nil)
		if err := os.WriteFile(filepath.Join(directory, name+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestSystemAppendReplaceRootIsolation$")
	command.Env = append(os.Environ(), "ZTMAIL_TEST_SYSTEM_ROOT_DIR="+directory, "SSL_CERT_FILE="+filepath.Join(directory, "system.pem"), "SSL_CERT_DIR="+t.TempDir())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("isolated system-root verifier: %v: %s", err, output)
	}
}
