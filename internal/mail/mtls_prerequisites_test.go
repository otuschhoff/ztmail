package mail

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"net/smtp"
	"net/textproto"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/addns"
	"github.com/otuschhoff/adbind/ad/dns"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/adbind/ad/observe"
	"golang.org/x/net/dns/dnsmessage"
)

func TestMTLSPrerequisiteDNSWithoutCredentialMethods(t *testing.T) {
	var workers sync.WaitGroup
	var queries atomic.Int32
	var forbidden atomic.Int32
	options := adclient.ADOptions{
		DNS: addns.Options{
			Domain: "example.test", RecursionProbeZone: "outside.test",
			QualificationPolicy: addns.QualificationOptimistic,
			Bootstrap:           []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53")},
			DNS: dns.Options{Timeout: 2 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != "192.0.2.53:53" && address != "[2001:db8::53]:53" {
					return nil, fmt.Errorf("unexpected DNS endpoint %q", address)
				}
				client, server := net.Pipe()
				if deadline, ok := ctx.Deadline(); ok {
					if err := client.SetDeadline(deadline); err != nil {
						client.Close()
						server.Close()
						return nil, err
					}
					if err := server.SetDeadline(deadline); err != nil {
						client.Close()
						server.Close()
						return nil, err
					}
				}
				workers.Add(1)
				go func() {
					defer workers.Done()
					defer server.Close()
					if err := prerequisiteDNSReply(server, network, &queries); err != nil {
						if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
							t.Logf("SDK canceled an unelected synthetic DNS lane: %v", err)
						} else {
							t.Errorf("DNS fixture: %v", err)
						}
					}
				}()
				return client, nil
			}},
		},
		Credentials: kerberos.Options{SourceMethods: []kerberos.Source{}, PrincipalMethods: []kerberos.PrincipalMethod{}},
		Protection:  "gss_seal",
		Hooks: observe.Hooks{Trace: func(_ context.Context, event observe.TraceEvent) {
			if event.Protocol == "kerberos" || event.Protocol == "ldap" {
				forbidden.Add(1)
			}
		}},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			forbidden.Add(1)
			return nil, errors.New("LDAP must not be dialed")
		},
	}
	owner, err := adclient.NewAD(options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := owner.Close(context.Background()); err != nil {
			t.Errorf("AD owner cleanup: %v", err)
		}
		workers.Wait()
	}()
	if queries.Load() != 0 {
		t.Fatal("NewAD performed DNS I/O")
	}
	addresses, err := (&ADBackend{Client: owner}).Resolve(t.Context(), "mailgw.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(addresses, netip.MustParseAddr("192.0.2.53")) || queries.Load() == 0 {
		t.Fatalf("relay not resolved through SDK DNS: %v", addresses)
	}
	status := owner.Credentials().SourceStatus()
	inventory := owner.DiscoveryInventory()
	if status.Pinned || len(status.Attempts) != 0 || inventory.Kerberos.Discovered ||
		inventory.LDAP.Discovered || forbidden.Load() != 0 {
		t.Fatalf("DNS initiated credential/native/KDC/LDAP work: source=%+v inventory=%+v forbidden=%d", status, inventory, forbidden.Load())
	}
}

func prerequisiteDNSReply(conn net.Conn, network string, queries *atomic.Int32) error {
	packet := make([]byte, 65535)
	var size int
	if network == "tcp" {
		var prefix [2]byte
		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return err
		}
		size = int(binary.BigEndian.Uint16(prefix[:]))
		if _, err := io.ReadFull(conn, packet[:size]); err != nil {
			return err
		}
	} else {
		var err error
		size, err = conn.Read(packet)
		if err != nil {
			return err
		}
	}
	var request dnsmessage.Message
	if err := request.Unpack(packet[:size]); err != nil {
		return err
	}
	queries.Add(1)
	reply := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: request.ID, Response: true, Authoritative: true, RecursionAvailable: true},
		Questions: request.Questions,
	}
	for _, question := range request.Questions {
		header := dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}
		var body dnsmessage.ResourceBody
		switch question.Type {
		case dnsmessage.TypeA:
			body = &dnsmessage.AResource{A: [4]byte{192, 0, 2, 53}}
		case dnsmessage.TypeAAAA:
			body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::53").As16()}
		case dnsmessage.TypeSOA:
			body = &dnsmessage.SOAResource{NS: dnsmessage.MustNewName("dc.example.test."), MBox: dnsmessage.MustNewName("hostmaster.example.test."), Serial: 1, Refresh: 60, Retry: 60, Expire: 3600, MinTTL: 60}
		case dnsmessage.TypeNS:
			body = &dnsmessage.NSResource{NS: dnsmessage.MustNewName("dc.example.test.")}
		case dnsmessage.TypeSRV:
			body = &dnsmessage.SRVResource{Target: dnsmessage.MustNewName("dc.example.test."), Port: 389}
		default:
			return fmt.Errorf("unexpected DNS question type %v", question.Type)
		}
		reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: body})
	}
	response, err := reply.Pack()
	if err != nil {
		return err
	}
	if network == "tcp" {
		response = append(binary.BigEndian.AppendUint16(nil, uint16(len(response))), response...)
	}
	_, err = conn.Write(response)
	return err
}

// This test-local prototype proves the existing client's command API can emit
// EXTERNAL's literal empty response without net/smtp.Auth's base64 conversion.
func prerequisiteExternal(c *smtp.Client) error {
	ok, mechanisms := c.Extension("AUTH")
	if !ok || !slices.ContainsFunc(strings.Fields(mechanisms), func(s string) bool { return strings.EqualFold(s, "EXTERNAL") }) {
		return errors.New("AUTH EXTERNAL not advertised")
	}
	command := func(value string) (int, string, error) {
		id, err := c.Text.Cmd("%s", value)
		if err != nil {
			return 0, "", err
		}
		c.Text.StartResponse(id)
		defer c.Text.EndResponse(id)
		return c.Text.ReadResponse(0)
	}
	code, message, err := command("AUTH EXTERNAL =")
	if err != nil {
		return err
	}
	if code == 334 {
		if message != "" {
			return errors.New("unexpected EXTERNAL challenge")
		}
		code, message, err = command("=")
		if err != nil {
			return err
		}
	}
	if code != 235 {
		return &textproto.Error{Code: code, Msg: message}
	}
	return nil
}

func TestMTLSPrerequisiteExternalWire(t *testing.T) {
	for _, tt := range []struct {
		name, first, final string
		wantError          bool
		wantContinuation   bool
	}{
		{"immediate-success", "235 2.7.0 OK", "", false, false},
		{"empty-continuation", "334 ", "235 2.7.0 OK", false, true},
		{"rejection", "535 5.7.8 rejected", "", true, false},
		{"nonempty-challenge", "334 YQ==", "", true, false},
		{"repeated-challenge", "334 ", "334 ", true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			deadline := time.Now().Add(2 * time.Second)
			if err := client.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := server.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				defer server.Close()
				reader := bufio.NewReader(server)
				exchange := func(reply, expected string) error {
					if _, err := fmt.Fprintf(server, "%s\r\n", reply); err != nil {
						return err
					}
					got, err := reader.ReadString('\n')
					if err != nil {
						return err
					}
					if got != expected+"\r\n" {
						return fmt.Errorf("wire=%q, want %q", got, expected+"\r\n")
					}
					return nil
				}
				err := exchange("220 relay.example.test", "EHLO localhost")
				if err == nil {
					err = exchange("250-relay.example.test\r\n250 AUTH eXtErNaL", "AUTH EXTERNAL =")
				}
				if err == nil && tt.wantContinuation {
					err = exchange(tt.first, "=")
				}
				reply := tt.first
				if tt.wantContinuation {
					reply = tt.final
				}
				if err == nil {
					_, err = fmt.Fprintf(server, "%s\r\n", reply)
				}
				result <- err
			}()
			c, err := smtp.NewClient(client, "relay.example.test")
			if err != nil {
				t.Fatal(err)
			}
			err = prerequisiteExternal(c)
			if (err != nil) != tt.wantError {
				t.Fatalf("EXTERNAL error=%v, wantError=%v", err, tt.wantError)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func prerequisiteCertificate(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func TestMTLSPrerequisiteParsedLeafExpiryIsNotSignedExpiry(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	root, rootKey := prerequisiteCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Prerequisite root"},
		NotBefore: now.Add(-365 * 24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, nil)
	leaf, _ := prerequisiteCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"relay.example.test"},
		NotBefore: now.Add(-30 * 24 * time.Hour), NotAfter: now.Add(-time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, root, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	options := x509.VerifyOptions{Roots: roots, DNSName: "relay.example.test", CurrentTime: now}
	_, err := leaf.Verify(options)
	var invalid x509.CertificateInvalidError
	if !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
		t.Fatalf("original expired leaf not rejected: %v", err)
	}
	parsedCopy := *leaf
	parsedCopy.NotAfter = now.Add(time.Second)
	if _, err := parsedCopy.Verify(options); err != nil {
		t.Fatalf("Go-only parsed-field prototype failed: %v", err)
	}
	derCopy, err := x509.ParseCertificate(parsedCopy.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if !derCopy.NotAfter.Equal(leaf.NotAfter) {
		t.Fatal("signed DER unexpectedly changed with parsed-field normalization")
	}
	if _, err := derCopy.Verify(options); !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
		t.Fatalf("DER-based verification did not reject original signed expiry: %v", err)
	}
}
