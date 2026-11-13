package mail

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tlsValidationSigner struct {
	crypto.Signer
}

func TestAuthenticationConfigRejectsTypedNilSigners(t *testing.T) {
	for _, tt := range []struct {
		name string
		key  crypto.Signer
	}{
		{"ecdsa", (*ecdsa.PrivateKey)(nil)},
		{"rsa", (*rsa.PrivateKey)(nil)},
		{"custom-pointer", (*tlsValidationSigner)(nil)},
		{"ed25519-slice", ed25519.PrivateKey(nil)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := tlsBenchConfig(t, 1, 0)
			input.ClientCertificate.PrivateKey = tt.key
			if _, err := PrepareAuthentication(input); err == nil || !strings.Contains(err.Error(), "client private key") {
				t.Fatalf("typed-nil signer must produce a configuration error: %v", err)
			}
		})
	}
}

func TestAuthenticationConfigPreservesCustomSigners(t *testing.T) {
	for _, name := range []string{"value", "pointer"} {
		t.Run(name, func(t *testing.T) {
			input := tlsBenchConfig(t, 2, 0)
			privateKey := input.ClientCertificate.PrivateKey.(ed25519.PrivateKey)
			var key crypto.Signer = &privateKey
			var signer crypto.Signer = tlsValidationSigner{key}
			if name == "pointer" {
				signer = &tlsValidationSigner{key}
			}
			input.ClientCertificate.PrivateKey = signer
			input.ClientCertificate.OCSPStaple = []byte("ocsp")
			input.ClientCertificate.SignedCertificateTimestamps = [][]byte{[]byte("sct")}
			out, err := PrepareAuthentication(input)
			if err != nil {
				t.Fatal(err)
			}
			if out.ClientCertificate.PrivateKey != signer {
				t.Fatal("custom signer was replaced instead of borrowed")
			}
			message := []byte("borrowed immutable signer")
			signature, err := out.ClientCertificate.PrivateKey.(crypto.Signer).Sign(bytes.NewReader(nil), message, crypto.Hash(0))
			if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), message, signature) {
				t.Fatalf("prepared custom signer cannot sign: %v", err)
			}
			for _, der := range input.ClientCertificate.Certificate {
				der[0] ^= 1
			}
			input.ClientCertificate.OCSPStaple[0] ^= 1
			input.ClientCertificate.SignedCertificateTimestamps[0][0] ^= 1
			input.ClientCertificate.SupportedSignatureAlgorithms[0] = tls.PSSWithSHA256
			if bytes.Equal(input.ClientCertificate.Certificate[0], out.ClientCertificate.Certificate[0]) ||
				bytes.Equal(input.ClientCertificate.Certificate[1], out.ClientCertificate.Certificate[1]) ||
				bytes.Equal(input.ClientCertificate.OCSPStaple, out.ClientCertificate.OCSPStaple) ||
				bytes.Equal(input.ClientCertificate.SignedCertificateTimestamps[0], out.ClientCertificate.SignedCertificateTimestamps[0]) ||
				out.ClientCertificate.SupportedSignatureAlgorithms[0] != tls.Ed25519 {
				t.Fatal("prepared custom certificate aliases mutable input")
			}
			mismatch := tlsBenchConfig(t, 1, 0)
			other, _ := tlsBenchCertificate(t, "different-client", false, nil, nil)
			mismatch.ClientCertificate.Certificate = [][]byte{other.Raw}
			mismatch.ClientCertificate.PrivateKey = signer
			if _, err := PrepareAuthentication(mismatch); err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("mismatched custom signer accepted: %v", err)
			}
		})
	}
}

func TestLoadServerCAsRejectsMalformedEntries(t *testing.T) {
	cert, _ := tlsBenchCertificate(t, "strict-root", true, nil, nil)
	valid := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	begin, end := "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
	for _, tt := range []struct {
		name string
		pem  string
	}{
		{"invalid-base64", begin + "\n!invalid!\n" + end + "\n"},
		{"empty-body", begin + "\n" + end + "\n"},
		{"missing-end", begin + "\nYQ==\n"},
		{"wrong-end", begin + "\nYQ==\n-----END PRIVATE KEY-----\n"},
		{"malformed-end", strings.Replace(valid, end, "-----END CERTIFICATE----", 1)},
		{"end-junk", strings.Replace(valid, end, end+"junk", 1)},
		{"end-not-on-line", strings.Replace(valid, "\n"+end, end, 1)},
		{"begin-junk", strings.Replace(valid, begin, begin+"junk", 1)},
		{"begin-not-on-line", "junk" + valid},
		{"nested-begin", begin + "\n!invalid!\n" + valid + end + "\n"},
		{"nested-valid", begin + "\n" + valid},
		{"extra-end", valid + end + "\n"},
		{"wrong-type", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: cert.Raw}))},
		{"header", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Comment": "not allowed"}, Bytes: cert.Raw}))},
		{"invalid-header", begin + "\nComment without colon\n" + strings.TrimPrefix(valid, begin+"\n")},
		{"der-error", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not DER")}))},
		{"trailing-junk", valid + "junk\n"},
		{"trailing-begin", valid + begin},
		{"end-before-begin", end + "\n" + valid},
		{"no-block-separator", strings.TrimSuffix(valid, "\n") + valid},
	} {
		for _, position := range []struct {
			name   string
			prefix string
			suffix string
		}{
			{"alone", "", ""},
			{"before", "", valid},
			{"among", valid, valid},
			{"after", valid, ""},
		} {
			t.Run(tt.name+"/"+position.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "roots.pem")
				if err := os.WriteFile(path, []byte(position.prefix+tt.pem+position.suffix), 0600); err != nil {
					t.Fatal(err)
				}
				got, err := LoadServerCAs(path)
				if err == nil || got != nil || !strings.Contains(err.Error(), "SMTP CA") {
					t.Fatalf("malformed CA entry must fail without partial roots: roots=%d error=%v", len(got), err)
				}
				if tt.name == "der-error" && !strings.Contains(err.Error(), "SMTP CA certificate:") {
					t.Fatalf("DER parse error lost certificate context: %v", err)
				}
			})
		}
	}
}

func TestLoadServerCAsValidBundles(t *testing.T) {
	first, _ := tlsBenchCertificate(t, "first-strict-root", true, nil, nil)
	second, _ := tlsBenchCertificate(t, "second-strict-root", true, nil, nil)
	firstPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first.Raw}))
	secondPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second.Raw}))
	for _, tt := range []struct {
		name string
		pem  string
	}{
		{"lf", firstPEM + secondPEM},
		{"crlf", strings.ReplaceAll(firstPEM+secondPEM, "\n", "\r\n")},
		{"whitespace", " \t\r\n" + firstPEM + "\n \t\r\n" + secondPEM + " \r\n\t"},
		{"no-final-newline", firstPEM + strings.TrimSuffix(secondPEM, "\n")},
		{"crlf-no-final-newline", strings.TrimSuffix(strings.ReplaceAll(firstPEM+secondPEM, "\n", "\r\n"), "\r\n")},
		{"marker-line-whitespace", strings.ReplaceAll(firstPEM+secondPEM, "-----\n", "----- \t\n")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "roots.pem")
			if err := os.WriteFile(path, []byte(tt.pem), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := LoadServerCAs(path)
			if err != nil || len(got) != 2 {
				t.Fatalf("valid bundle: roots=%d error=%v", len(got), err)
			}
			if !bytes.Equal(got[0], first.Raw) || !bytes.Equal(got[1], second.Raw) {
				t.Fatal("loader changed certificate DER or order")
			}
			got[0][0] ^= 1
			again, err := LoadServerCAs(path)
			if err != nil || !bytes.Equal(again[0], first.Raw) {
				t.Fatalf("loaded roots share caller-mutable storage: %v", err)
			}
		})
	}
}
