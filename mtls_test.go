package ztmail

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type libraryResolver struct{}

func (libraryResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

func TestLibraryMTLSEndToEnd(t *testing.T) {
	for _, mode := range []string{"send", "null", "test", "recipient", "uncertain", "quit", "cli"} {
		t.Run(mode, func(t *testing.T) {
			ad := testAD(t)
			clientCert := libraryClientCertificate(t)
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Synthetic SMTP root"},
				DNSNames: []string{"relay.corp.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			clientLeaf, err := x509.ParseCertificate(clientCert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			clientRoots := x509.NewCertPool()
			clientRoots.AddCert(clientLeaf)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			wire := make(chan wireResult, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					wire <- wireResult{err: err}
					return
				}
				wire <- smtpPeer(tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12,
					ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientRoots,
					Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}), mode)
			}()
			client, err := New(Options{AD: ad, Domain: "corp.example", Relay: "relay.corp.example",
				Port: listener.Addr().(*net.TCPAddr).Port, TLS: TLSImplicit, Auth: AuthMTLSExternal,
				ClientCertificate: clientCert, ServerTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{der}}})
			if err != nil {
				t.Fatal(err)
			}
			client.resolver = libraryResolver{}
			client.acquire = func(context.Context) (session, error) {
				t.Fatal("mTLS invoked credential/LDAP session")
				return nil, errors.New("unexpected credentials")
			}
			data := []byte("From: Original <original@corp.example>\r\nBcc: hidden@corp.example\r\nTo: receiver@corp.example\r\nSubject: Private\r\n\r\nBody\r\n")
			original := bytes.Clone(data)
			message := Message{From: "sender@corp.example", Data: data}
			if mode == "null" {
				message.From = "<>"
			}
			var result Result
			if mode == "cli" {
				err = cliCertificateSubmission(t, client, clientCert, der, data)
				if err != nil {
					listener.Close()
					t.Fatal(err)
				}
			} else if mode == "test" {
				result, err = client.Test(context.Background(), io.Discard)
			} else {
				result, err = client.Send(context.Background(), message)
			}
			peer := <-wire
			if mode == "cli" {
				if err != nil || peer.err != nil || !bytes.Contains(peer.message, []byte("Body")) ||
					bytes.Contains(peer.message, []byte("Bcc:")) {
					t.Fatalf("CLI mTLS failed: %v peer=%+v", err, peer)
				}
				return
			}
			switch mode {
			case "recipient":
				if err == nil || errors.Is(err, ErrDeliveryUncertain) || bytes.Contains(peer.message, []byte("Body")) {
					t.Fatalf("recipient rejection reached DATA or became uncertain: %v", err)
				}

			case "uncertain":
				if !errors.Is(err, ErrDeliveryUncertain) || result.Accepted {
					t.Fatalf("uncertain acceptance lost: %+v %v", result, err)
				}
			default:
				if err != nil || result.Accepted != (mode != "test") || !result.Authentication.SMTPAuthConfirmed ||
					!result.Authentication.ClientCertificatePresented || result.Identity.Principal != "" {
					t.Fatalf("result=%+v err=%v peer=%v", result, err, peer.err)
				}
				if mode == "quit" && len(result.Warnings) == 0 {
					t.Fatal("accepted QUIT failure lost warning")
				}
			}
			if mode == "test" {
				for _, command := range peer.commands {
					if strings.HasPrefix(command, "MAIL ") || strings.HasPrefix(command, "RCPT ") || command == "DATA" {
						t.Fatalf("Test sent an envelope: %v", peer.commands)
					}
				}
			} else if mode != "recipient" {
				if bytes.Contains(peer.message, []byte("Bcc:")) || !bytes.Equal(data, original) {
					t.Fatal("Bcc leaked or caller input mutated")
				}
				if mode == "null" && (!bytes.Contains(peer.message, []byte("Original <original@corp.example>")) || result.From != "") {
					t.Fatalf("null envelope/header preservation lost: %+v", result)
				}
			}
			if status := ad.Credentials().SourceStatus(); status.Pinned || len(status.Attempts) != 0 {
				t.Fatalf("borrowed owner credentials mutated: %+v", status)
			}
		})
	}
}

func cliCertificateSubmission(t *testing.T, client *Client, certificate *tls.Certificate, caDER, data []byte) error {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("real CLI integration uses an isolated Linux loopback DNS listener on port 53")
	}
	directory := t.TempDir()
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, block := range map[string]*pem.Block{
		"client.pem": {Type: "CERTIFICATE", Bytes: certificate.Certificate[0]},
		"client.key": {Type: "PRIVATE KEY", Bytes: keyDER},
		"root.pem":   {Type: "CERTIFICATE", Bytes: caDER},
	} {
		if err := os.WriteFile(filepath.Join(directory, name), pem.EncodeToMemory(block), 0600); err != nil {
			t.Fatal(err)
		}
	}
	dns, err := net.ListenPacket("udp", "127.0.0.2:53")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skip("authorized scope: isolated CLI DNS port 53 is unavailable; SDK/transport/library tests remain required")
		}
		t.Fatal(err)
	}
	defer dns.Close()
	dnsDone := make(chan struct{})
	go func() {
		defer close(dnsDone)
		packet := make([]byte, 65535)
		for {
			n, peer, err := dns.ReadFrom(packet)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if err := request.Unpack(packet[:n]); err != nil {
				t.Error(err)
				return
			}
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: request.Header.ID, Response: true,
				Authoritative: true, RecursionDesired: request.Header.RecursionDesired, RecursionAvailable: true},
				Questions: request.Questions}
			for _, question := range request.Questions {
				var body dnsmessage.ResourceBody
				switch question.Type {
				case dnsmessage.TypeA:
					address := [4]byte{127, 0, 0, 2}
					if question.Name.String() == "relay.corp.example." {
						address[3] = 1
					}
					body = &dnsmessage.AResource{A: address}
				case dnsmessage.TypeAAAA:
					body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("::ffff:127.0.0.2").As16()}
				case dnsmessage.TypeNS:
					body = &dnsmessage.NSResource{NS: dnsmessage.MustNewName("dc.corp.example.")}
				case dnsmessage.TypeSOA:
					body = &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("dc.corp.example."),
						MBox: dnsmessage.MustNewName("hostmaster.corp.example."), Serial: 1, Refresh: 60, Retry: 60, Expire: 3600, MinTTL: 60}
				case dnsmessage.TypeSRV:
					body = &dnsmessage.SRVResource{Target: dnsmessage.MustNewName("dc.corp.example."), Port: 389}
				default:
					t.Errorf("unexpected CLI SDK DNS query: %v", question.Type)
					return
				}
				reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{
					Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: body})
			}
			response, err := reply.Pack()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := dns.WriteTo(response, peer); err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
				return
			}
		}
	}()
	defer func() { dns.Close(); <-dnsDone }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	executable := filepath.Join(directory, "ztmail")
	build := exec.CommandContext(ctx, "go", "build", "-o", executable, "./cmd/ztmail")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v: %s", err, output)
	}
	command := exec.CommandContext(ctx, executable, "--auth=mtls-external", "--domain=corp.example", "--timeout=5s",
		"--hostname=worker.corp.example", "--relay=relay.corp.example", fmt.Sprintf("--port=%d", client.options.Port),
		"--tls=implicit", "--tls-ca-mode=replace", "--tls-ca="+filepath.Join(directory, "root.pem"),
		"--client-cert="+filepath.Join(directory, "client.pem"), "--client-key="+filepath.Join(directory, "client.key"),
		"--dns-server="+dns.LocalAddr().String(), "-f", "sender@corp.example", "-t")
	command.Stdin = bytes.NewReader(data)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("CLI: %w: %s", err, output)
	}
	return nil
}

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
	if _, err := client.Send(context.Background(), Message{Data: []byte("To: recipient@example.com\r\nSubject: Test\r\n\r\nBody\r\n")}); err == nil || !strings.Contains(err.Error(), "requires Message.From") {
		t.Fatalf("mTLS fell through to credential acquisition: %v", err)
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
