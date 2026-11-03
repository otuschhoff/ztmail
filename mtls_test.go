package ztmail

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func libraryClientCertificate(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Library client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestLibraryMTLSConfigurationAndNoFallthrough(t *testing.T) {
	ad := testAD(t)
	cert := libraryClientCertificate(t)
	client, err := New(Options{AD: ad, Domain: "corp.example", Auth: AuthMTLSExternal, ClientCertificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	cert.Certificate[0][0] ^= 1
	if client.options.ClientCertificate.Certificate[0][0] == cert.Certificate[0][0] {
		t.Fatal("library certificate DER aliases caller")
	}
	if _, err := client.Send(context.Background(), Message{}); err == nil || !strings.Contains(err.Error(), "not yet wired") {
		t.Fatalf("Phase 1 mTLS fell through to credential acquisition: %v", err)
	}
	if status := ad.Credentials().SourceStatus(); status.Pinned || len(status.Attempts) != 0 {
		t.Fatalf("library selected credentials: %+v", status)
	}
	for _, change := range []func(*Options){
		func(o *Options) { o.SPN = "smtp/relay" },
		func(o *Options) { o.Realm = "CORP.EXAMPLE" },
		func(o *Options) { o.LDAPRaceCandidates = 8 },
		func(o *Options) { o.TLS = TLSOff },
	} {
		input := Options{AD: ad, Domain: "corp.example", Auth: AuthMTLS, ClientCertificate: libraryClientCertificate(t)}
		change(&input)
		if _, err := New(input); err == nil {
			t.Fatal("contradictory library mTLS options accepted")
		}
	}
}
