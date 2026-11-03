package ztmail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/textproto"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/addns"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/ztmail/internal/mail"
)

func testAD(t *testing.T) *adclient.Client {
	t.Helper()
	trust, err := adclient.NewTrust(adclient.TrustPolicy{Protection: "tls"})
	if err != nil {
		t.Fatal(err)
	}
	ad, err := adclient.NewAD(adclient.ADOptions{
		DNS:   addns.Options{Domain: "corp.example", RecursionProbeZone: "example.com"},
		Trust: trust, Protection: "tls",
		Credentials: kerberos.Options{Source: kerberos.SourceCCache, Realm: "CORP.EXAMPLE",
			CCache: filepath.Join(t.TempDir(), "missing-cache")},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := ad.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return ad
}

func TestNewDefaultsAndValidation(t *testing.T) {
	ad := testAD(t)
	base := Options{AD: ad, Domain: "CORP.EXAMPLE."}
	client, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	o := client.options
	if o.Domain != "corp.example" || o.Realm != "CORP.EXAMPLE" || o.Relay != "mailgw.corp.example" ||
		o.Hostname != "localhost" || o.SPN != "smtp/mailgw.corp.example" || o.Port != 25 || o.Timeout != time.Minute || o.TLS != TLSRequired ||
		o.LDAPRaceCandidates != 0 {
		t.Fatalf("unexpected defaults: %+v", o)
	}
	for _, invalid := range []func(*Options){
		func(o *Options) { o.AD = nil },
		func(o *Options) { o.AD = &adclient.Client{} },
		func(o *Options) { o.Domain = "" },
		func(o *Options) { o.Domain = "192.0.2.1" },
		func(o *Options) { o.Realm = "INVALID\nREALM" },
		func(o *Options) { o.Relay = "relay:25" },
		func(o *Options) { o.Hostname = "bad hostname" },
		func(o *Options) { o.SPN = "smtp/relay\r\n" },
		func(o *Options) { o.Port = -1 },
		func(o *Options) { o.Port = 65536 },
		func(o *Options) { o.TLS = "invalid" },
		func(o *Options) { o.Timeout = -time.Second },
		func(o *Options) { o.LDAPRaceCandidates = -1 },
		func(o *Options) { o.LDAPRaceCandidates = 9 },
	} {
		o := base
		invalid(&o)
		if _, err := New(o); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	dns, err := ad.DNS()
	if err != nil || dns.Snapshot().Closed {
		t.Fatal("New closed the borrowed AD client")
	}
}

func TestNewLDAPRaceOptIn(t *testing.T) {
	ad := testAD(t)
	for _, count := range []int{0, 1, 8} {
		options := Options{AD: ad, Domain: "corp.example", LDAPRaceCandidates: count}
		client, err := New(options)
		if err != nil {
			t.Fatal(err)
		}
		options.LDAPRaceCandidates = 9
		if client.options.LDAPRaceCandidates != count {
			t.Fatal("New did not preserve the independently copied LDAP policy")
		}
		dns, err := ad.DNS()
		if err != nil || dns.Snapshot().Closed {
			t.Fatal("LDAP policy configuration closed the borrowed owner")
		}
	}
}

func TestRealBorrowedADFailureDoesNotCloseOwner(t *testing.T) {
	ad := testAD(t)
	client, err := New(Options{AD: ad, Domain: "corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Send(context.Background(), Message{Recipients: []string{"user@corp.example"},
		Data: []byte("Subject: test\r\n\r\nBody.\r\n")})
	if err == nil || result.Accepted {
		t.Fatal("missing cache unexpectedly authenticated")
	}
	dns, err := ad.DNS()
	if err != nil || dns.Snapshot().Closed {
		t.Fatal("Send closed the borrowed DNS owner")
	}
	_, err = ad.Credentials().Acquire(context.Background())
	if errors.Is(err, kerberos.ErrClosed) {
		t.Fatal("Send closed the borrowed credentials owner")
	}
}

type fakeSession struct {
	canonicalCalls, releases, contexts atomic.Int32
	identityValue                      kerberos.Identity
	identityErr, ticketErr, mailErr    error
	securityErr, cleanupErr            error
	hostWithoutMail                    bool
	ctxWork                            func(context.Context) error
}

func (s *fakeSession) identity() (kerberos.Identity, error) { return s.identityValue, s.identityErr }
func (s *fakeSession) ticket(ctx context.Context, _ string) error {
	if s.ctxWork != nil {
		return s.ctxWork(ctx)
	}
	return s.ticketErr
}
func (s *fakeSession) canonical(context.Context, kerberos.Identity) (mail.CanonicalMailbox, error) {
	s.canonicalCalls.Add(1)
	if s.hostWithoutMail {
		return mail.CanonicalMailbox{HostWithoutMail: true}, s.mailErr
	}
	return mail.CanonicalMailbox{Address: "alice@corp.example"}, s.mailErr
}
func (s *fakeSession) release() { s.releases.Add(1) }
func (s *fakeSession) Resolve(context.Context, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}
func (s *fakeSession) NewSecurityContext(context.Context, string, *tls.ConnectionState) (mail.SecurityContext, error) {
	s.contexts.Add(1)
	return &fakeContext{cleanupErr: s.cleanupErr}, s.securityErr
}

type fakeContext struct{ cleanupErr error }

func (*fakeContext) Start() ([]byte, error)            { return []byte("initial"), nil }
func (*fakeContext) Step([]byte) ([]byte, bool, error) { return nil, true, nil }
func (*fakeContext) Negotiate([]byte) ([]byte, error)  { return []byte("selection"), nil }
func (c *fakeContext) Close() error                    { return c.cleanupErr }

func newSession() *fakeSession {
	return &fakeSession{identityValue: kerberos.Identity{Principal: "alice@CORP.EXAMPLE", Realm: "CORP.EXAMPLE", Source: kerberos.SourceCCache}}
}

func testClient(t *testing.T, s *fakeSession) *Client {
	t.Helper()
	client, err := New(Options{AD: testAD(t), Domain: "corp.example", TLS: TLSOff, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client.acquire = func(context.Context) (session, error) { return s, nil }
	return client
}

type wireResult struct {
	commands []string
	message  []byte
	err      error
}

func smtpPeer(conn net.Conn, mode string) (result wireResult) {
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		result.err = err
		return
	}
	reader := textproto.NewReader(bufio.NewReader(conn))
	writer := bufio.NewWriter(conn)
	reply := func(line string) error {
		_, err := fmt.Fprintf(writer, "%s\r\n", line)
		if err == nil {
			err = writer.Flush()
		}
		return err
	}
	if result.err = reply("220 synthetic ESMTP"); result.err != nil {
		return
	}
	authStage := 0
	for {
		var line string
		line, result.err = reader.ReadLine()
		if result.err != nil {
			return
		}
		result.commands = append(result.commands, line)
		response := "250 OK"
		switch {
		case strings.HasPrefix(line, "EHLO "):
			response = "250-synthetic\r\n250 AUTH GSSAPI EXTERNAL"
		case line == "AUTH EXTERNAL =":
			response = "235 authenticated"
		case strings.HasPrefix(line, "AUTH GSSAPI "):
			if mode == "auth" {
				response = "535 Authentication rejected"
			} else {
				response = "334 " + base64.StdEncoding.EncodeToString([]byte("mutual"))
				authStage = 1
			}
		case authStage == 1:
			authStage = 2
			response = "334 " + base64.StdEncoding.EncodeToString([]byte("offer"))
		case authStage == 2:
			authStage = 0
			response = "235 authenticated"
		case strings.HasPrefix(line, "MAIL FROM:"):
		case strings.HasPrefix(line, "RCPT TO:"):
			if mode == "recipient" {
				response = "550 Recipient rejected"
			}
		case line == "DATA":
			if result.err = reply("354 Send data"); result.err != nil {
				return
			}
			result.message, result.err = io.ReadAll(reader.DotReader())
			if result.err != nil || mode == "uncertain" {
				return
			}
		case line == "QUIT":
			if mode != "quit" {
				result.err = reply("221 Bye")
			}
			return
		default:
			result.err = fmt.Errorf("unexpected command %q", line)
			return
		}
		if result.err = reply(response); result.err != nil {
			return
		}
	}
}

func server(t *testing.T, mode string) (int, <-chan wireResult) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	results := make(chan wireResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- wireResult{err: err}
			return
		}
		results <- smtpPeer(conn, mode)
	}()
	return listener.Addr().(*net.TCPAddr).Port, results
}

func TestSendAndOwnership(t *testing.T) {
	for _, mode := range []string{"canonical", "override", "null", "override-racing", "null-racing", "quit", "cleanup", "auth", "recipient", "uncertain", "security"} {
		t.Run(mode, func(t *testing.T) {
			s := newSession()
			client := testClient(t, s)
			if strings.HasSuffix(mode, "-racing") {
				client.options.LDAPRaceCandidates = 8
				mode = strings.TrimSuffix(mode, "-racing")
			}
			port, wire := server(t, mode)
			client.options.Port = port
			message := Message{Recipients: []string{"recipient@corp.example"},
				Data:           []byte("From: original@corp.example\r\nSender: original@corp.example\r\nBcc: blind@corp.example\r\nSubject: test\r\n\r\n.\r\nBody.\r\n"),
				ReadRecipients: true}
			if mode == "override" {
				message.From = "override@corp.example"
			} else if mode == "null" {
				message.From = "<>"
			}
			if mode == "cleanup" {
				s.cleanupErr = errors.New("synthetic context cleanup")
			}
			if mode == "security" {
				s.securityErr = errors.New("synthetic context creation failure")
			}
			original := append([]byte(nil), message.Data...)
			result, err := client.Send(context.Background(), message)
			record := <-wire
			failure := mode == "auth" || mode == "recipient" || mode == "uncertain" || mode == "security"
			if failure {
				if err == nil || result.Accepted {
					t.Fatalf("failure accepted: %+v err=%v", result, err)
				}
				if mode == "uncertain" && !errors.Is(err, ErrDeliveryUncertain) {
					t.Fatalf("uncertain delivery not classified: %v", err)
				}
				if mode != "uncertain" && errors.Is(err, ErrDeliveryUncertain) {
					t.Fatalf("pre-DATA failure incorrectly marked uncertain: %v", err)
				}
			} else {
				if err != nil || !result.Accepted || record.err != nil {
					t.Fatalf("result=%+v client=%v server=%v", result, err, record.err)
				}
				if bytes.Contains(record.message, []byte("Bcc:")) || !bytes.Contains(record.message, []byte("\n.\nBody.\n")) {
					t.Fatalf("message filtering/dot handling: %q", record.message)
				}
				sender := "alice@corp.example"
				if mode == "override" {
					sender = message.From
				} else if mode == "null" {
					sender = ""
				}
				if result.From != sender || result.Identity.Principal != s.identityValue.Principal || len(result.Recipients) != 2 {
					t.Fatalf("unexpected result: %+v", result)
				}
				if mode == "null" {
					if !bytes.Contains(record.message, []byte("From: original@corp.example")) {
						t.Fatal("null sender rewrote headers")
					}
				} else if !bytes.Contains(record.message, []byte("From: <"+sender+">")) {
					t.Fatalf("sender not rewritten: %q", record.message)
				}
				warning := mode == "quit" || mode == "cleanup"
				if (len(result.Warnings) != 0) != warning {
					t.Fatalf("post-acceptance warnings=%v", result.Warnings)
				}
				if mode == "cleanup" && !errors.Is(result.Warnings[0], s.cleanupErr) {
					t.Fatal("post-acceptance cleanup warning lost its cause")
				}
				dataCommands := 0
				for _, command := range record.commands {
					if command == "DATA" {
						dataCommands++
					}
				}
				if dataCommands != 1 {
					t.Fatalf("submission was retried: DATA count=%d", dataCommands)
				}
			}
			if !bytes.Equal(message.Data, original) || len(message.Recipients) != 1 || s.releases.Load() != 1 || s.contexts.Load() != 1 {
				t.Fatal("caller data mutated or lease/context lifetime incorrect")
			}
			lookup := mode != "override" && mode != "null"
			if (s.canonicalCalls.Load() != 0) != lookup {
				t.Fatal("incorrect canonical-mail lookup policy")
			}
		})
	}
}

func TestRecipientFallbackSend(t *testing.T) {
	for _, mode := range []string{"headers", "self", "override-self", "null-self"} {
		t.Run(mode, func(t *testing.T) {
			s := newSession()
			client := testClient(t, s)
			port, wire := server(t, "canonical")
			client.options.Port = port
			message := Message{Data: []byte("Subject: self\n\nbody\n")}
			want := "alice@corp.example"
			switch mode {
			case "headers":
				message.Data = []byte("To: header@corp.example\nBcc: blind@corp.example\n\nbody\n")
				want = "header@corp.example"
			case "override-self":
				message.From = "override@corp.example"
			case "null-self":
				message.From = "<>"
			}
			result, err := client.Send(context.Background(), message)
			record := <-wire
			if err != nil || record.err != nil || !result.Accepted || len(result.Recipients) == 0 || result.Recipients[0] != want {
				t.Fatalf("fallback delivery: result=%+v err=%v wire=%v", result, err, record.err)
			}
			if !strings.Contains(strings.Join(record.commands, "\n"), "RCPT TO:<"+want+">") ||
				strings.Contains(string(record.message), "Bcc:") {
				t.Fatalf("incorrect envelope or Bcc disclosure: %+v", record)
			}
			if s.canonicalCalls.Load() != 1 {
				t.Fatal("self fallback must obtain authenticated canonical mail even with sender override")
			}
		})
	}
}

func TestHostWithoutMailboxCanAuthenticateWithoutEmail(t *testing.T) {
	s := newSession()
	s.identityValue.Principal = "HOST$@CORP.EXAMPLE"
	s.hostWithoutMail = true
	client := testClient(t, s)
	port, wire := server(t, "canonical")
	client.options.Port = port
	var report bytes.Buffer
	result, err := client.Test(t.Context(), &report)
	record := <-wire
	if err != nil || record.err != nil || result.Accepted || s.canonicalCalls.Load() != 1 || s.releases.Load() != 1 {
		t.Fatalf("host authentication: result=%+v err=%v wire=%v calls=%d releases=%d",
			result, err, record.err, s.canonicalCalls.Load(), s.releases.Load())
	}
	if !strings.Contains(report.String(), "[WARN] Canonical AD mail lookup") ||
		strings.Contains(report.String(), "[FAIL] Canonical AD mail lookup") {
		t.Fatalf("missing host mailbox warning or false failure: %s", &report)
	}
	for _, command := range record.commands {
		if strings.HasPrefix(command, "MAIL FROM:") || command == "DATA" {
			t.Fatalf("no-email host test submitted an envelope: %v", record.commands)
		}
	}
}

func TestHostMailboxLookupFailureIsStillFatal(t *testing.T) {
	s := newSession()
	s.hostWithoutMail = true
	s.mailErr = errors.New("LDAP cleanup failed")
	client := testClient(t, s)
	var report bytes.Buffer
	if _, err := client.Test(t.Context(), &report); !errors.Is(err, s.mailErr) {
		t.Fatalf("host classification suppressed a real lookup/cleanup error: %v", err)
	}
	if strings.Contains(report.String(), "[WARN] Canonical AD mail lookup") ||
		!strings.Contains(report.String(), "[FAIL] Canonical AD mail lookup") || s.releases.Load() != 1 {
		t.Fatalf("real host lookup failure was not reported/released: %s", &report)
	}
}

func TestHostMissingMailboxRequiresSenderForSubmission(t *testing.T) {
	s := newSession()
	s.hostWithoutMail = true
	client := testClient(t, s)
	result, err := client.Send(t.Context(), Message{Recipients: []string{"recipient@corp.example"},
		Data: []byte("Subject: test\r\n\r\nBody.\r\n")})
	if err == nil || !strings.Contains(err.Error(), "specify Message.From") || result.Accepted || s.contexts.Load() != 0 {
		t.Fatalf("host submitted without a sender: %+v %v", result, err)
	}
}

func TestHostSubmissionWithExplicitSenderAndRecipients(t *testing.T) {
	for _, from := range []string{"sender@corp.example", "<>"} {
		t.Run(from, func(t *testing.T) {
			s := newSession()
			s.identityValue.Principal = "HOST$@CORP.EXAMPLE"
			s.hostWithoutMail = true
			client := testClient(t, s)
			port, wire := server(t, "canonical")
			client.options.Port = port
			result, err := client.Send(t.Context(), Message{
				From: from, Recipients: []string{"recipient@corp.example"},
				Data: []byte("From: original@corp.example\r\nSubject: test\r\n\r\nBody.\r\n"),
			})
			record := <-wire
			want := from
			if from == "<>" {
				want = ""
			}
			if err != nil || record.err != nil || !result.Accepted || result.From != want ||
				s.canonicalCalls.Load() != 0 || s.releases.Load() != 1 {
				t.Fatalf("host submission with known sender/recipient: %+v err=%v wire=%v calls=%d",
					result, err, record.err, s.canonicalCalls.Load())
			}
			if from == "<>" && !strings.Contains(string(record.message), "From: original@corp.example") {
				t.Fatal("host null envelope rewrote the original sender")
			}
		})
	}
}

func TestValidationBeforeCredentialAcquisition(t *testing.T) {
	client := testClient(t, newSession())
	client.acquire = func(context.Context) (session, error) {
		t.Fatal("invalid request acquired credentials")
		return nil, nil
	}
	for _, message := range []Message{
		{}, {Data: []byte("Subject: malformed\nbody\n"), Recipients: []string{"user@corp.example"}},
		{Data: []byte("Subject: valid\n\nbody\n"), Recipients: []string{"invalid\r\nrecipient"}},
		{Data: []byte("Subject: valid\n\nbody\n"), From: "bad\r\nsender"},
	} {
		if _, err := client.Send(context.Background(), message); err == nil {
			t.Fatal("invalid message accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Send(ctx, Message{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	if _, err := client.Send(nil, Message{}); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := client.Test(context.Background(), nil); err == nil {
		t.Fatal("nil report accepted")
	}
	if _, err := (&Client{}).Send(context.Background(), Message{}); err == nil {
		t.Fatal("zero client accepted")
	}
}

func TestAcquisitionFailureAndReportErrors(t *testing.T) {
	client := testClient(t, newSession())
	sourceErr := errors.New("SDK credential capacity reached")
	client.acquire = func(context.Context) (session, error) { return nil, sourceErr }
	result, err := client.Send(context.Background(), Message{Data: []byte("Subject: valid\n\nBody.\n"),
		Recipients: []string{"user@corp.example"}})
	if !errors.Is(err, sourceErr) || result.Accepted {
		t.Fatalf("acquisition failure lost: %v", err)
	}
	var report bytes.Buffer
	if _, err := client.Test(context.Background(), &report); !errors.Is(err, sourceErr) {
		t.Fatalf("test acquisition failure lost: %v", err)
	}
	if !strings.Contains(report.String(), "[FAIL] Acquire credential lease") || !strings.Contains(report.String(), "[FAIL] Test") {
		t.Fatalf("missing failed-step report: %s", &report)
	}
	writeErr := errors.New("report output unavailable")
	if _, err := client.Test(context.Background(), brokenWriter{writeErr}); !errors.Is(err, writeErr) || !errors.Is(err, sourceErr) {
		t.Fatalf("report or acquisition failure lost: %v", err)
	}
}

type brokenWriter struct{ err error }

func (w brokenWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCredentialFailuresReleaseLease(t *testing.T) {
	for _, stage := range []string{"identity", "realm", "ticket", "canonical", "context"} {
		t.Run(stage, func(t *testing.T) {
			s := newSession()
			failure := errors.New("synthetic failure")
			switch stage {
			case "identity":
				s.identityErr = failure
			case "realm":
				s.identityValue.Realm = "OTHER.EXAMPLE"
			case "ticket":
				s.ticketErr = failure
			case "canonical":
				s.mailErr = failure
			case "context":
				s.ctxWork = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
			}
			client := testClient(t, s)
			client.options.Timeout = 10 * time.Millisecond
			_, err := client.Send(context.Background(), Message{Recipients: []string{"user@corp.example"},
				Data: []byte("Subject: valid\n\nBody.\n")})
			if err == nil || s.releases.Load() != 1 {
				t.Fatalf("lease leak: %v", err)
			}
			if stage == "context" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("timeout not enforced: %v", err)
			}
			if stage != "context" && stage != "realm" && !errors.Is(err, failure) {
				t.Fatalf("lost SDK error: %v", err)
			}
		})
	}
}

func TestLibraryTestNeverSendsEmail(t *testing.T) {
	s := newSession()
	client := testClient(t, s)
	port, wire := server(t, "")
	client.options.Port = port
	var report bytes.Buffer
	result, err := client.Test(context.Background(), &report)
	record := <-wire
	if err != nil || result.Accepted || record.err != nil || len(record.message) != 0 || s.releases.Load() != 1 {
		t.Fatalf("result=%+v err=%v wire=%v", result, err, record.err)
	}
	for _, command := range record.commands {
		if strings.HasPrefix(command, "MAIL ") || strings.HasPrefix(command, "RCPT ") || command == "DATA" {
			t.Fatalf("test sent %q", command)
		}
	}
	if !strings.Contains(report.String(), "Authentication") || !strings.Contains(report.String(), "OK") || !strings.Contains(report.String(), "Total runtime") {
		t.Fatalf("missing report: %s", &report)
	}
	for _, value := range []string{"Authentication method", "GSSAPI", "SPN", client.options.SPN} {
		if !strings.Contains(report.String(), value) {
			t.Errorf("missing library report value %q:\n%s", value, &report)
		}
	}
}

func TestConcurrentCallsUseIndependentLeasesAndContexts(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const count = 8
	serverErrors := make(chan error, count)
	go func() {
		for range count {
			conn, err := listener.Accept()
			if err != nil {
				serverErrors <- err
				continue
			}
			go func() { serverErrors <- smtpPeer(conn, "").err }()
		}
	}()
	client := testClient(t, newSession())
	client.options.Port = listener.Addr().(*net.TCPAddr).Port
	var sessionsMu sync.Mutex
	var sessions []*fakeSession
	client.acquire = func(context.Context) (session, error) {
		s := newSession()
		sessionsMu.Lock()
		sessions = append(sessions, s)
		sessionsMu.Unlock()
		return s, nil
	}
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := client.Send(context.Background(), Message{Data: []byte("Subject: concurrent\n\nBody.\n"),
				Recipients: []string{"user@corp.example"}})
			if err != nil || !result.Accepted {
				t.Errorf("send=%+v err=%v", result, err)
			}
		}()
	}
	wg.Wait()
	for range count {
		if err := <-serverErrors; err != nil {
			t.Fatal(err)
		}
	}
	if len(sessions) != count {
		t.Fatalf("leases=%d", len(sessions))
	}
	for _, s := range sessions {
		if s.releases.Load() != 1 || s.contexts.Load() != 1 {
			t.Fatal("concurrent operation reused or leaked a lease/context")
		}
	}
}
