package ztmail

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/ztmail/internal/mail"
)

type quotedMailboxSession struct {
	*fakeSession
	mailbox string
}

func (s *quotedMailboxSession) canonical(context.Context, kerberos.Identity) (mail.CanonicalMailbox, error) {
	s.canonicalCalls.Add(1)
	return mail.CanonicalMailbox{Address: s.mailbox}, nil
}

func TestLibraryQuotedMailboxWireCommands(t *testing.T) {
	for _, tc := range []struct {
		name, input, wire string
	}{
		{"space", `"a b"@corp.example`, `"a b"@corp.example`},
		{"quote", `"a\"b"@corp.example`, `"a\"b"@corp.example`},
		{"backslash", `"a\\b"@corp.example`, `"a\\b"@corp.example`},
		{"dots", `"a..b"@corp.example`, `"a..b"@corp.example`},
		{"quoted atom", `"alice"@corp.example`, "alice@corp.example"},
	} {
		for _, surface := range []string{"explicit", "headers", "canonical-self"} {
			t.Run(tc.name+"/"+surface, func(t *testing.T) {
				s := newSession()
				client := testClient(t, s)
				port, wire := server(t, "canonical")
				client.options.Port = port
				client.acquire = func(context.Context) (session, error) {
					return &quotedMailboxSession{fakeSession: s, mailbox: tc.input}, nil
				}
				message := Message{Data: []byte("Subject: test\r\n\r\n.\r\nBody.\r\n")}
				if surface == "explicit" {
					message.From = tc.input
					message.Recipients = []string{tc.input}
				} else if surface == "headers" {
					message.Data = []byte("To: " + tc.input + "\r\nBcc: " + tc.input + "\r\nSubject: test\r\n\r\n.\r\nBody.\r\n")
				}
				original := bytes.Clone(message.Data)
				result, err := client.Send(t.Context(), message)
				if err != nil {
					t.Fatal(err)
				}
				record := <-wire
				if record.err != nil || !result.Accepted || result.From != tc.wire ||
					!reflect.DeepEqual(result.Recipients, []string{tc.wire}) {
					t.Fatalf("result=%+v peer=%v", result, record.err)
				}
				for _, command := range []string{"MAIL FROM:<" + tc.wire + ">", "RCPT TO:<" + tc.wire + ">"} {
					count := 0
					for _, actual := range record.commands {
						if actual == command {
							count++
						}
					}
					if count != 1 {
						t.Fatalf("command %q count=%d in %q", command, count, record.commands)
					}
				}
				if !bytes.Equal(message.Data, original) || bytes.Contains(record.message, []byte("Bcc:")) ||
					!bytes.Contains(record.message, []byte("From: <"+tc.wire+">")) ||
					!bytes.HasSuffix(record.message, []byte("\n.\nBody.\n")) {
					t.Fatalf("message immutability/privacy/body failed: %q", record.message)
				}
				wantLookups := int32(1)
				if surface == "explicit" {
					wantLookups = 0
				}
				if s.canonicalCalls.Load() != wantLookups || s.releases.Load() != 1 || s.contexts.Load() != 1 {
					t.Fatal("lookup/lease/context ownership changed")
				}
			})
		}
	}
}

func TestLibraryInvalidHeaderNamesFailBeforeAcquisition(t *testing.T) {
	client := testClient(t, newSession())
	client.acquire = func(context.Context) (session, error) {
		t.Fatal("invalid header acquired credentials")
		return nil, nil
	}
	for _, name := range []string{"Bcc ", "Bcc\t", "Resent-Bcc ", "Bad Name", "Bad\x00Name", "Bad\x7fName", "Bad\xffName"} {
		t.Run(name, func(t *testing.T) {
			message := Message{Data: []byte(name + ": hidden@corp.example\r\n\tfolded\r\n\r\nbody\r\n"),
				Recipients: []string{"recipient@corp.example"}}
			result, err := client.Send(t.Context(), message)
			if err == nil || result.Accepted || !strings.Contains(err.Error(), "invalid RFC 5322 message") {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

type forbiddenValidationResolver struct{ t *testing.T }

func (r forbiddenValidationResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	r.t.Fatal("invalid message attempted DNS/SMTP work")
	return nil, nil
}

func TestLibraryInvalidQuotedMailboxesFailBeforeEffects(t *testing.T) {
	for _, auth := range []AuthMode{AuthGSSAPI, AuthMTLS, AuthMTLSExternal} {
		t.Run(string(auth), func(t *testing.T) {
			var client *Client
			if auth == AuthGSSAPI {
				client = testClient(t, newSession())
			} else {
				var err error
				client, err = New(Options{AD: testAD(t), Domain: "corp.example", Auth: auth, ClientCertificate: libraryClientCertificate(t)})
				if err != nil {
					t.Fatal(err)
				}
			}
			client.acquire = func(context.Context) (session, error) {
				t.Fatal("invalid mailbox acquired credentials")
				return nil, nil
			}
			client.resolver = forbiddenValidationResolver{t}
			for _, input := range []string{`"a b@corp.example`, `a b@corp.example`, `"a"suffix@corp.example`,
				`""@corp.example`, `"a b"@corp.example,other@corp.example`, "\"a\nb\"@corp.example"} {
				for _, surface := range []string{"sender", "recipient", "header"} {
					if surface == "header" && strings.Contains(input, ",") {
						continue
					}
					t.Run(input+"/"+surface, func(t *testing.T) {
						message := Message{From: "sender@corp.example", Recipients: []string{"recipient@corp.example"},
							Data: []byte("Subject: test\n\nbody\n")}
						switch surface {
						case "sender":
							message.From = input
						case "recipient":
							message.Recipients = []string{input}
						case "header":
							message.Recipients = nil
							message.Data = []byte("To: " + input + "\n\nbody\n")
						}
						result, err := client.Send(t.Context(), message)
						if err == nil || result.Accepted {
							t.Fatalf("invalid %s accepted: %+v err=%v", surface, result, err)
						}
					})
				}
			}
		})
	}
}

type nilLibrarySigner struct{ crypto.Signer }

func TestLibraryConstructorRejectsTypedNilSigners(t *testing.T) {
	ad := testAD(t)
	var ecdsaKey *ecdsa.PrivateKey
	var rsaKey *rsa.PrivateKey
	var ed25519Key ed25519.PrivateKey
	var customKey *nilLibrarySigner
	for _, tc := range []struct {
		name string
		key  any
	}{{"ecdsa", ecdsaKey}, {"rsa", rsaKey}, {"ed25519", ed25519Key}, {"custom", customKey}} {
		t.Run(tc.name, func(t *testing.T) {
			certificate := libraryClientCertificate(t)
			certificate.PrivateKey = tc.key
			client, err := New(Options{AD: ad, Domain: "corp.example", Auth: AuthMTLS, ClientCertificate: certificate})
			if err == nil || client != nil {
				t.Fatalf("invalid signer accepted: client=%v err=%v", client, err)
			}
			if status := ad.Credentials().SourceStatus(); status.Pinned || len(status.Attempts) != 0 {
				t.Fatalf("invalid construction acquired credentials: %+v", status)
			}
			dns, err := ad.DNS()
			if err != nil || dns.Snapshot().Closed {
				t.Fatal("invalid construction closed borrowed AD")
			}
		})
	}
}
