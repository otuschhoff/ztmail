package mail

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func tlsBenchCertificate(tb testing.TB, name string, ca bool, parent *x509.Certificate, signer ed25519.PrivateKey) (*x509.Certificate, ed25519.PrivateKey) {
	tb.Helper()
	seed := sha256.Sum256([]byte("ztmail synthetic benchmark key: " + name))
	key := ed25519.NewKeyFromSeed(seed[:])
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(seed[:16]), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:      ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if ca {
		template.KeyUsage |= x509.KeyUsageCertSign
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if parent == nil {
		parent, signer = template, key
	}
	// Ed25519 signing is deterministic and does not consume entropy.
	der, err := x509.CreateCertificate(bytes.NewReader(nil), template, parent, key.Public(), signer)
	if err != nil {
		tb.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return cert, key
}

func tlsBenchConfig(tb testing.TB, chainSize, bundleSize int) Config {
	tb.Helper()
	config := Config{Auth: AuthGSSAPI, TLSMode: "required", ServerTrust: ServerTrust{Mode: RootsSystem}}
	if chainSize > 0 {
		var parent *x509.Certificate
		var signer ed25519.PrivateKey
		chain := make([][]byte, chainSize)
		for i := chainSize - 1; i >= 0; i-- {
			cert, key := tlsBenchCertificate(tb, fmt.Sprintf("client-chain-%d", i), i > 0, parent, signer)
			chain[i], parent, signer = cert.Raw, cert, key
		}
		config.Auth = AuthMTLS
		config.ClientCertificate = &tls.Certificate{
			Certificate: chain, PrivateKey: signer,
			SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.Ed25519},
		}
	}
	if bundleSize > 0 {
		config.ServerTrust.Mode = RootsReplace
		for i := 0; i < bundleSize; i++ {
			ca, _ := tlsBenchCertificate(tb, fmt.Sprintf("server-root-%d", i), true, nil, nil)
			config.ServerTrust.Certificates = append(config.ServerTrust.Certificates, ca.Raw)
			config.ServerTrust.Allow = append(config.ServerTrust.Allow, CASelector{
				Kind: CACertificateSHA256, Digest: sha256.Sum256(ca.Raw),
			})
			config.ServerTrust.Deny = append(config.ServerTrust.Deny, CASelector{
				Kind: CASPKISHA256, Digest: sha256.Sum256([]byte(fmt.Sprintf("unrelated-denied-key-%d", i))),
			})
		}
	}
	return config
}

func BenchmarkPrepareAuthentication(b *testing.B) {
	for _, chain := range []int{0, 1, 2, 4, 8} {
		for _, bundle := range []int{0, 1, 8, 32, 128} {
			b.Run(fmt.Sprintf("Chain/%d/Bundle/%d", chain, bundle), func(b *testing.B) {
				input := tlsBenchConfig(b, chain, bundle)
				b.ReportAllocs()
				for b.Loop() {
					out, err := PrepareAuthentication(input)
					if err != nil || out.Auth != input.Auth || len(out.ServerTrust.Certificates) != bundle ||
						len(out.ServerTrust.Allow) != bundle || len(out.ServerTrust.Deny) != bundle {
						b.Fatalf("authentication shape: %v", err)
					}
					if chain > 0 && (out.ClientCertificate == nil || out.ClientCertificate.Leaf == nil ||
						len(out.ClientCertificate.Certificate) != chain) {
						b.Fatal("missing client certificate chain")
					}
					if chain == 0 && out.ClientCertificate != nil {
						b.Fatal("GSSAPI acquired a certificate")
					}
				}
			})
		}
	}
}

func BenchmarkServerRoots(b *testing.B) {
	for _, size := range []int{1, 8, 32, 128} {
		b.Run(fmt.Sprintf("Replace/%d", size), func(b *testing.B) {
			trust := tlsBenchConfig(b, 0, size).ServerTrust
			b.ReportAllocs()
			for b.Loop() {
				roots, err := serverRoots(trust)
				if err != nil || roots == nil {
					b.Fatalf("server roots: %v", err)
				}
			}
		})
	}
}

func BenchmarkRepeatedCertificateDelivery(b *testing.B) {
	for _, bundle := range []int{1, 32} {
		for _, size := range []int{1 << 10, 1 << 20} {
			for _, method := range []AuthMode{AuthMTLS, AuthMTLSExternal} {
				b.Run(fmt.Sprintf("%s/roots=%d/bytes=%d", method, bundle, size), func(b *testing.B) {
					config, deliver := repeatedCertificateDeliveryFixture(b, method, bundle, size)
					b.ReportAllocs()
					b.SetBytes(int64(size))
					for b.Loop() {
						if err := deliver(b.Context(), config); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		}
	}
}

func BenchmarkConcurrentCertificateDelivery(b *testing.B) {
	const calls = 4
	for _, bundle := range []int{1, 32} {
		for _, size := range []int{1 << 10, 1 << 20} {
			b.Run(fmt.Sprintf("calls=%d/roots=%d/bytes=%d", calls, bundle, size), func(b *testing.B) {
				var configs [calls]Config
				var send [calls]func(context.Context, Config) error
				for i := range configs {
					configs[i], send[i] = repeatedCertificateDeliveryFixture(b, AuthMTLSExternal, bundle, size)
				}
				var workers sync.WaitGroup
				b.Cleanup(workers.Wait)
				b.ReportAllocs()
				b.SetBytes(int64(calls * size))
				for b.Loop() {
					results := make(chan error, calls)
					for i := range configs {
						workers.Go(func() { results <- send[i](b.Context(), configs[i]) })
					}
					workers.Wait()
					for range calls {
						if err := <-results; err != nil {
							b.Fatal(err)
						}
					}
				}
			})
		}
	}
}

func repeatedCertificateDeliveryFixture(tb testing.TB, method AuthMode, bundle, size int) (Config, func(context.Context, Config) error) {
	tb.Helper()
	fixture := newCertificateSMTPFixture(tb)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	var workers sync.WaitGroup
	tb.Cleanup(func() { listener.Close(); workers.Wait() })
	results := make(chan smtpResult, 1)
	workers.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			results <- serveCertificateSMTP(conn, fixture, true, true, false)
		}
	})
	var auth AuthenticationResult
	config := Config{Auth: method, Relay: "relay.example.test", Hello: "host.example.test", TLSMode: "implicit",
		Port: listener.Addr().(*net.TCPAddr).Port, Timeout: 5 * time.Second,
		ClientCertificate: fixture.client, ServerTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}},
		From: "sender@corp.example", Warning: func(error) {}, Authentication: func(value AuthenticationResult) { auth = value }}
	config.ClientCertificate.Certificate = append(config.ClientCertificate.Certificate, fixture.ca.Raw)
	if bundle > 1 {
		extra := tlsBenchConfig(tb, 0, bundle-1)
		config.ServerTrust.Certificates = append(config.ServerTrust.Certificates, extra.ServerTrust.Certificates...)
	}
	// Like an already constructed library client, own validated input before repeated operations.
	config, err = PrepareAuthentication(config)
	if err != nil {
		tb.Fatal(err)
	}
	header := []byte("Subject: synthetic TLS delivery benchmark\r\n\r\n")
	message := bytes.Repeat([]byte{'x'}, size)
	copy(message, header)
	for i := len(header); i < len(message); i++ {
		switch (i - len(header)) % 76 {
		case 74:
			message[i] = '\r'
		case 75:
			message[i] = '\n'
		}
	}
	message = append(message, '\r', '\n')
	expected := strings.ReplaceAll(string(message), "\r\n", "\n")
	return config, func(ctx context.Context, config Config) error {
		auth = AuthenticationResult{}
		err := Deliver(ctx, config, []string{"recipient@corp.example"}, message, certificateResolver{netip.MustParseAddr("127.0.0.1")}, io.Discard)
		if err != nil {
			return err
		}
		result := <-results
		dataCount := 0
		for _, command := range result.commands {
			if command == "DATA" {
				dataCount++
			}
		}
		if result.err != nil || result.message != expected || dataCount != 1 ||
			!auth.TLSEstablished || !auth.ClientCertificatePresented || !auth.ServerVerification.Trusted ||
			auth.SMTPAuthConfirmed != (method == AuthMTLSExternal) {
			return fmt.Errorf("incorrect repeated TLS delivery: server=%v DATA=%d bytes=%d authentication=%+v",
				result.err, dataCount, len(result.message), auth)
		}
		return nil
	}
}

func TestBenchmarkRepeatedCertificateDeliveryFixture(t *testing.T) {
	for _, method := range []AuthMode{AuthMTLS, AuthMTLSExternal} {
		for _, bundle := range []int{1, 32} {
			t.Run(fmt.Sprintf("%s/roots=%d", method, bundle), func(t *testing.T) {
				config, deliver := repeatedCertificateDeliveryFixture(t, method, bundle, 1<<10)
				for range 2 {
					if err := deliver(t.Context(), config); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}

func TestBenchmarkTLSCredentialsFixtures(t *testing.T) {
	for _, chain := range []int{0, 1, 2, 4, 8} {
		for _, bundle := range []int{0, 1, 8, 32, 128} {
			t.Run(fmt.Sprintf("Chain/%d/Bundle/%d", chain, bundle), func(t *testing.T) {
				input := tlsBenchConfig(t, chain, bundle)
				snapshot := tlsBenchConfig(t, chain, bundle)
				out, err := PrepareAuthentication(input)
				if err != nil || !reflect.DeepEqual(input, snapshot) {
					t.Fatalf("authentication error or input mutation: %v", err)
				}
				if chain > 0 {
					if err := validateClientCertificate(out.ClientCertificate, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
						t.Fatal(err)
					}
					for i, der := range out.ClientCertificate.Certificate {
						cert, err := x509.ParseCertificate(der)
						if err != nil {
							t.Fatal(err)
						}
						if i+1 < chain {
							parent, err := x509.ParseCertificate(out.ClientCertificate.Certificate[i+1])
							if err != nil {
								t.Fatal(err)
							}
							if err := cert.CheckSignatureFrom(parent); err != nil {
								t.Fatal(err)
							}
						} else if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
							t.Fatal(err)
						}
						input.ClientCertificate.Certificate[i][0] ^= 1
					}
					input.ClientCertificate.SupportedSignatureAlgorithms[0] = tls.PSSWithSHA256
				}
				if bundle > 0 {
					roots, err := serverRoots(out.ServerTrust)
					if err != nil || len(roots.Subjects()) != bundle {
						t.Fatalf("distinct replacement roots: %v", err)
					}
					for i, der := range out.ServerTrust.Certificates {
						ca, err := x509.ParseCertificate(der)
						if err != nil || !selectorMatches(out.ServerTrust.Allow[i], ca) ||
							selectorMatches(out.ServerTrust.Deny[i], ca) {
							t.Fatalf("CA selector fixture: %v", err)
						}
						input.ServerTrust.Certificates[i][0] ^= 1
						input.ServerTrust.Allow[i].Digest[0] ^= 1
						input.ServerTrust.Deny[i].Digest[0] ^= 1
					}
				}
				expected, err := PrepareAuthentication(snapshot)
				actualView, expectedView := out, expected
				actualView.preparedTrust, expectedView.preparedTrust = nil, nil
				if err != nil || !reflect.DeepEqual(actualView, expectedView) {
					t.Fatalf("prepared output aliases mutable fixture input: %v", err)
				}
				if bundle > 0 && (!reflect.DeepEqual(out.preparedTrust.certificates, expected.preparedTrust.certificates) ||
					!out.preparedTrust.replaceRoots.Equal(expected.preparedTrust.replaceRoots)) {
					t.Fatal("prepared CA parser data aliases mutable fixture input")
				}
			})
		}
	}
}
