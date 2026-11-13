package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	stdmail "net/mail"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/ztmail/internal/mail"
)

type commandHarness struct {
	deps                                        commandDependencies
	events                                      []string
	releases, closes, dnsCloses, terminals      int
	sourceErr, passwordErr, deliveryErr         error
	closeErr, terminalErr, discoveryErr, dnsErr error
	hostWithoutMail                             bool
	terminal                                    *fakePasswordTerminal
	inspect                                     func(context.Context, operationOptions, []string, []byte)
}

func newCommandHarness(t *testing.T) *commandHarness {
	t.Helper()
	h := &commandHarness{deps: systemDependencies(),
		terminal: &fakePasswordTerminal{input: strings.NewReader("\n"), password: []byte("synthetic-secret")}}
	h.deps.discoverHost = func(context.Context, string) (string, string, error) {
		h.events = append(h.events, "host")
		return "host.corp.example", "corp.example", h.discoveryErr
	}
	h.deps.currentUser = func() (*user.User, error) {
		h.events = append(h.events, "user")
		return &user.User{Username: "alice"}, nil
	}
	h.deps.openTerminal = func() (passwordTerminal, error) {
		h.events = append(h.events, "terminal")
		return harnessTerminal{h: h}, nil
	}
	h.deps.attemptAD = func(ctx context.Context, o operationOptions, settings adclient.ADOptions) (*adSession, error) {
		h.events = append(h.events, "ad:"+string(settings.Credentials.Source))
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Error("credential stage has no operation deadline")
		}
		if settings.Credentials.Source == kerberos.SourcePassword {
			if settings.Credentials.Password != "synthetic-secret" || settings.Credentials.Principal != "alice@CORP.EXAMPLE" {
				t.Error("password assembly lost selected principal or secret")
			}
			if h.passwordErr != nil {
				return nil, h.passwordErr
			}
		} else if h.sourceErr != nil {
			return nil, h.sourceErr
		}
		canonical := "alice@corp.example"
		if h.hostWithoutMail {
			canonical = ""
		}
		return &adSession{
			identity: kerberos.Identity{Principal: "alice@CORP.EXAMPLE", Realm: "CORP.EXAMPLE", Source: settings.Credentials.Source},
			mail:     canonical, hostWithoutMail: h.hostWithoutMail, report: o.report,
			releaseLease: func() { h.releases++; h.events = append(h.events, "release") },
			closeOwner: func(cleanup context.Context) error {
				if cleanup.Err() != nil {
					t.Error("owner cleanup inherited cancellation")
				}
				h.closes++
				h.events = append(h.events, "close-ad")
				return h.closeErr
			},
		}, nil
	}
	h.deps.newDNSOwner = func(settings adclient.ADOptions) (dnsOwner, error) {
		h.events = append(h.events, "dns-owner")
		if settings.Credentials.SourceMethods == nil || len(settings.Credentials.SourceMethods) != 0 ||
			settings.Credentials.PrincipalMethods == nil || len(settings.Credentials.PrincipalMethods) != 0 {
			t.Error("certificate owner enables credential discovery")
		}
		if h.dnsErr != nil {
			return nil, h.dnsErr
		}
		return harnessDNSOwner{h: h}, nil
	}
	h.deps.deliver = func(ctx context.Context, o operationOptions, recipients []string, message []byte, _ submissionBackend, _ io.Writer) error {
		h.events = append(h.events, "deliver")
		if h.closes != 0 || h.dnsCloses != 0 {
			t.Error("owner closed before delivery")
		}
		if h.inspect != nil {
			h.inspect(ctx, o, recipients, message)
		}
		return h.deliveryErr
	}
	h.deps.fallback = func(_ context.Context, _ operationOptions, _ []string, _ []byte, _ string, _ error, _ io.Writer) error {
		h.events = append(h.events, "fallback")
		return nil
	}
	return h
}

type harnessTerminal struct{ h *commandHarness }

func (t harnessTerminal) Read(p []byte) (int, error)    { return t.h.terminal.Read(p) }
func (t harnessTerminal) Write(p []byte) (int, error)   { return t.h.terminal.Write(p) }
func (t harnessTerminal) ReadPassword() ([]byte, error) { return t.h.terminal.ReadPassword() }
func (t harnessTerminal) Close() error {
	t.h.terminals++
	t.h.events = append(t.h.events, "close-terminal")
	return t.h.terminalErr
}

type harnessDNSOwner struct{ h *commandHarness }

func (o harnessDNSOwner) Resolve(context.Context, string) ([]netip.Addr, error) {
	panic("mock delivery must not resolve or contact a network")
}
func (o harnessDNSOwner) Close(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	o.h.dnsCloses++
	o.h.events = append(o.h.events, "close-dns")
	return o.h.closeErr
}

type stageReader struct {
	h *commandHarness
	r io.Reader
}

func (r *stageReader) Read(p []byte) (int, error) {
	if r.r == nil {
		r.h.events = append(r.h.events, "stdin")
		r.r = strings.NewReader("Subject: synthetic\r\n\r\nbody\r\n")
	}
	return r.r.Read(p)
}

func (h *commandHarness) execute(t *testing.T, args ...string) error {
	t.Helper()
	cmd := newCommandWithDependencies(h.deps)
	cmd.SetArgs(args)
	cmd.SetIn(&stageReader{h: h})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd.ExecuteContext(t.Context())
}

func TestCommandGSSAPIStageOrderAndOwnership(t *testing.T) {
	for _, mode := range []string{"send", "test", "testmail", "acquisition-error", "delivery-error", "cleanup-warning",
		"test-cleanup-error", "relay-fallback", "fallback-cleanup-error", "host-fallback", "uncertain", "accepted-output"} {
		t.Run(mode, func(t *testing.T) {
			isolatedSenderConfig(t)
			h := newCommandHarness(t)
			cause := errors.New("injected boundary failure")
			args := []string{"--domain=corp.example", "--from=sender@corp.example", "recipient@corp.example"}
			want := []string{"host", "stdin", "ad:ccache", "deliver", "release", "close-ad"}
			wantErr := false
			switch mode {
			case "test", "test-cleanup-error":
				args = []string{"--test", "--domain=corp.example"}
				want = []string{"host", "ad:ccache", "deliver", "release", "close-ad"}
				if mode == "test-cleanup-error" {
					h.closeErr, wantErr = cause, true
				}
			case "testmail":
				args = []string{"--testmail", "--domain=corp.example"}
				want = []string{"host", "ad:ccache", "deliver", "release", "close-ad"}
			case "acquisition-error":
				h.sourceErr, wantErr = cause, true
				want = []string{"host", "stdin", "ad:ccache"}
			case "delivery-error":
				h.deliveryErr, wantErr = cause, true
			case "uncertain":
				h.deliveryErr, wantErr = errors.Join(cause, mail.ErrDeliveryUncertain), true
			case "accepted-output":
				h.deliveryErr, wantErr = errors.Join(cause, mail.ErrAcceptedOutput), true
			case "cleanup-warning":
				h.closeErr = cause
			case "relay-fallback", "fallback-cleanup-error":
				if runtime.GOOS != "linux" {
					t.Skip("native fallback is Linux-only")
				}
				h.deliveryErr = errors.Join(cause, mail.ErrRelayUnavailable)
				want = []string{"host", "stdin", "ad:ccache", "deliver", "release", "close-ad", "fallback"}
				if mode == "fallback-cleanup-error" {
					h.closeErr, wantErr = cause, true
					want = want[:len(want)-1]
				}
			case "host-fallback":
				if runtime.GOOS != "linux" {
					t.Skip("native fallback is Linux-only")
				}
				h.discoveryErr = errors.Join(cause, errHostDomainUnavailable)
				want = []string{"host", "stdin", "fallback"}
			}
			h.inspect = func(_ context.Context, o operationOptions, recipients []string, message []byte) {
				if o.testMode && len(message) != 0 {
					t.Error("test prepared email")
				}
				if o.testMail && (len(message) != 0 || !reflect.DeepEqual(recipients, []string{"alice@corp.example"})) {
					t.Errorf("testmail assembly: recipients=%v bytes=%d", recipients, len(message))
				}
				if !o.testMode && !o.testMail {
					parsed, err := stdmail.ReadMessage(strings.NewReader(string(message)))
					if err != nil {
						t.Fatal(err)
					}
					sender, err := stdmail.ParseAddress(parsed.Header.Get("From"))
					if err != nil || sender.Address != "sender@corp.example" || o.from != "sender@corp.example" {
						t.Errorf("GSSAPI sender rewrite: header=%q envelope=%q err=%v", parsed.Header.Get("From"), o.from, err)
					}
				}
			}
			err := h.execute(t, args...)
			if !reflect.DeepEqual(h.events, want) || (err != nil) != wantErr ||
				(wantErr && !errors.Is(err, cause)) || h.releases != h.closes {
				t.Fatalf("events=%v want=%v releases=%d closes=%d err=%v", h.events, want, h.releases, h.closes, err)
			}
		})
	}
}

type delayedCommandReader struct {
	reader io.Reader
	wait   time.Duration
}

func (r *delayedCommandReader) Read(p []byte) (int, error) {
	time.Sleep(r.wait)
	r.wait = 0
	return r.reader.Read(p)
}

func TestCommandTimeoutStageBudgets(t *testing.T) {
	for _, password := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "password-fallback"}[password], func(t *testing.T) {
			isolatedSenderConfig(t)
			synctest.Test(t, func(t *testing.T) {
				h := newCommandHarness(t)
				start := time.Now()
				attempt := h.deps.attemptAD
				h.deps.attemptAD = func(ctx context.Context, o operationOptions, settings adclient.ADOptions) (*adSession, error) {
					deadline, ok := ctx.Deadline()
					if !ok || deadline.Sub(time.Now()) != time.Second {
						t.Fatalf("stage did not get a fresh deadline: %v present=%t", deadline, ok)
					}
					if password && settings.Credentials.Source != kerberos.SourcePassword {
						h.events = append(h.events, "expired-source")
						<-ctx.Done()
						return nil, ctx.Err()
					}
					return attempt(ctx, o, settings)
				}
				h.terminal.onPasswordRead = func() { time.Sleep(2 * time.Second) }
				cmd := newCommandWithDependencies(h.deps)
				args := []string{"--timeout=1s", "--domain=corp.example", "--from=sender@corp.example", "recipient@corp.example"}
				if password {
					args = append(args, "--password-prompt")
				}
				cmd.SetArgs(args)
				cmd.SetIn(&delayedCommandReader{reader: &stageReader{h: h}, wait: 3 * time.Second})
				cmd.SetErr(io.Discard)
				if err := cmd.ExecuteContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				wantTime := 3 * time.Second
				if password {
					wantTime = 6 * time.Second
					if runtime.GOOS == "windows" {
						wantTime += time.Second
					}
				}
				if time.Since(start) != wantTime || h.releases != 1 || h.closes != 1 {
					t.Fatalf("elapsed=%v want=%v releases=%d closes=%d", time.Since(start), wantTime, h.releases, h.closes)
				}
			})
		})
	}
}

func TestCommandCancellationDuringPasswordClosesTerminal(t *testing.T) {
	isolatedSenderConfig(t)
	h := newCommandHarness(t)
	h.sourceErr = errADCredentialsUnavailable
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h.terminal.onPasswordRead = cancel
	cmd := newCommandWithDependencies(h.deps)
	cmd.SetArgs([]string{"--test", "--password-prompt", "--domain=corp.example"})
	cmd.SetIn(forbiddenReader{})
	cmd.SetErr(io.Discard)
	err := cmd.ExecuteContext(ctx)
	if !errors.Is(err, context.Canceled) || h.terminals != 1 || h.releases != 0 || h.closes != 0 ||
		strings.Contains(strings.Join(h.events, ","), "ad:password") {
		t.Fatalf("canceled password stage leaked/continued: %v terminal-closes=%d err=%v", h.events, h.terminals, err)
	}
	for _, b := range h.terminal.password {
		if b != 0 {
			t.Fatal("canceled password retained")
		}
	}
}

func TestCommandPasswordAssemblyAndDefaultLookup(t *testing.T) {
	for _, mode := range []string{"send", "lookup", "local-user-error", "terminal-open-error", "terminal-close-error",
		"prompt-error", "password-error", "owner-close-error"} {
		t.Run(mode, func(t *testing.T) {
			isolatedSenderConfig(t)
			h := newCommandHarness(t)
			h.sourceErr = errADCredentialsUnavailable
			cause := errors.New("password boundary failed")
			args := []string{"--password-prompt", "--domain=corp.example", "--from=sender@corp.example", "recipient@corp.example"}
			want := []string{"host", "stdin", "ad:ccache", "user", "terminal", "close-terminal", "ad:password", "deliver", "release", "close-ad"}
			wantErr := false
			wantTerminals := 1
			switch mode {
			case "lookup":
				args = []string{"--set-default-from-ad", "--domain=corp.example"}
				want = []string{"host", "ad:ccache", "user", "terminal", "close-terminal", "ad:password", "release", "close-ad"}
			case "local-user-error":
				h.deps.currentUser = func() (*user.User, error) {
					h.events = append(h.events, "user")
					return nil, cause
				}
				want, wantErr, wantTerminals = want[:4], true, 0
			case "terminal-open-error":
				h.deps.openTerminal = func() (passwordTerminal, error) {
					h.events = append(h.events, "terminal")
					return nil, cause
				}
				want, wantErr, wantTerminals = want[:5], true, 0
			case "terminal-close-error":
				h.terminalErr, wantErr = cause, true
				want = want[:6]
			case "prompt-error":
				h.terminal.passwordErr, wantErr = cause, true
				want = want[:6]
			case "password-error":
				h.passwordErr, wantErr = cause, true
				want = want[:7]
			case "owner-close-error":
				args = []string{"--set-default-from-ad", "--domain=corp.example"}
				h.closeErr, wantErr = cause, true
				want = []string{"host", "ad:ccache", "user", "terminal", "close-terminal", "ad:password", "release", "close-ad"}
			}
			if runtime.GOOS == "windows" {
				for index, event := range want {
					if event == "ad:ccache" {
						want = slices.Insert(want, index+1, "ad:sspi")
						break
					}
				}
			}
			err := h.execute(t, args...)
			if !reflect.DeepEqual(h.events, want) || h.terminals != wantTerminals || h.releases != h.closes ||
				(err != nil) != wantErr || (wantErr && !errors.Is(err, cause)) {
				t.Fatalf("events=%v want=%v terminal-closes=%d err=%v", h.events, want, h.terminals, err)
			}
			if h.terminal.passwordReads > 0 {
				for _, b := range h.terminal.password {
					if b != 0 {
						t.Fatal("password bytes not cleared")
					}
				}
			}
			address, readErr := readDefaultSender()
			if readErr != nil || (address != "") != (mode == "lookup") {
				t.Fatalf("persisted address=%q err=%v", address, readErr)
			}
		})
	}
}

func TestCommandPreservesDeliveryAndCleanupFailures(t *testing.T) {
	for _, auth := range []string{"gssapi", "mtls", "mtls-external"} {
		t.Run(auth, func(t *testing.T) {
			isolatedSenderConfig(t)
			h := newCommandHarness(t)
			deliveryErr, cleanupErr := errors.New("delivery boundary failed"), errors.New("cleanup boundary failed")
			h.deliveryErr, h.closeErr = errors.Join(deliveryErr, mail.ErrRelayUnavailable), cleanupErr
			args := []string{"--auth=" + auth, "--domain=corp.example", "--from=sender@corp.example", "recipient@corp.example"}
			want := []string{"host", "stdin", "ad:ccache", "deliver", "release", "close-ad"}
			if auth != "gssapi" {
				cert, key := commandCertificateFiles(t)
				args = append(args, "--client-cert="+cert, "--client-key="+key)
				want = []string{"host", "stdin", "dns-owner", "deliver", "close-dns"}
			}
			err := h.execute(t, args...)
			if !errors.Is(err, deliveryErr) || !errors.Is(err, cleanupErr) || !errors.Is(err, mail.ErrRelayUnavailable) ||
				errors.Is(err, mail.ErrAcceptedOutput) || !reflect.DeepEqual(h.events, want) {
				t.Fatalf("lost cause, leaked owner or replayed after cleanup failure: events=%v err=%v", h.events, err)
			}
		})
	}
}

func TestCommandSenderAndOwnRecipientPolicy(t *testing.T) {
	for _, mode := range []string{"saved", "explicit", "null", "own-recipient", "host-without-sender",
		"host-testmail", "host-null-testmail", "lookup-host-without-mail"} {
		t.Run(mode, func(t *testing.T) {
			isolatedSenderConfig(t)
			h := newCommandHarness(t)
			args := []string{"--domain=corp.example", "recipient@corp.example"}
			wantFrom, wantRecipients := "alice@corp.example", []string{"recipient@corp.example"}
			want := []string{"host", "stdin", "ad:ccache", "deliver", "release", "close-ad"}
			wantErr := ""
			switch mode {
			case "saved", "explicit", "null":
				if _, err := writeDefaultSender("saved@corp.example"); err != nil {
					t.Fatal(err)
				}
				wantFrom = "saved@corp.example"
				if mode == "explicit" {
					args, wantFrom = append(args, "--from=explicit@corp.example"), "explicit@corp.example"
				} else if mode == "null" {
					args, wantFrom = append(args, "--from=<>"), ""
				}
			case "own-recipient":
				args, wantRecipients = args[:1], []string{"alice@corp.example"}
			case "host-without-sender":
				h.hostWithoutMail = true
				wantErr = "specify a sender"
				want = []string{"host", "stdin", "ad:ccache", "release", "close-ad"}
			case "host-testmail", "host-null-testmail":
				h.hostWithoutMail = true
				args = []string{"--domain=corp.example", "--testmail", "--from=sender@corp.example"}
				wantFrom, wantRecipients = "sender@corp.example", []string{"sender@corp.example"}
				want = []string{"host", "ad:ccache", "deliver", "release", "close-ad"}
				if mode == "host-null-testmail" {
					args[2], wantErr = "--from=<>", "requires a non-null"
					want = []string{"host", "ad:ccache", "release", "close-ad"}
				}
			case "lookup-host-without-mail":
				h.hostWithoutMail = true
				args, wantErr = []string{"--set-default-from-ad", "--domain=corp.example"}, "no canonical AD mailbox to save"
				want = []string{"host", "ad:ccache", "release", "close-ad"}
			}
			h.inspect = func(_ context.Context, o operationOptions, recipients []string, message []byte) {
				if o.from != wantFrom || !reflect.DeepEqual(recipients, wantRecipients) {
					t.Errorf("sender/recipient policy: sender=%q recipients=%v", o.from, recipients)
				}
				if mode == "null" {
					parsed, err := stdmail.ReadMessage(strings.NewReader(string(message)))
					if err != nil || parsed.Header.Get("From") != "" {
						t.Errorf("null sender rewrote original headers: %v", err)
					}
				}
			}
			err := h.execute(t, args...)
			if !reflect.DeepEqual(h.events, want) || h.releases != 1 || h.closes != 1 ||
				(wantErr == "" && err != nil) || (wantErr != "" && (err == nil || !strings.Contains(err.Error(), wantErr))) {
				t.Fatalf("sender policy events=%v want=%v err=%v", h.events, want, err)
			}
			if mode == "lookup-host-without-mail" {
				if address, err := readDefaultSender(); err != nil || address != "" {
					t.Fatalf("persisted unusable host mailbox: %q err=%v", address, err)
				}
			}
		})
	}
}

func TestCommandStateIsPerExecution(t *testing.T) {
	isolatedSenderConfig(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, public, private)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(rootPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"one.example", "two.example"} {
		t.Run(domain, func(t *testing.T) {
			t.Parallel()
			h := newCommandHarness(t)
			h.deps.discoverHost = func(_ context.Context, requested string) (string, string, error) {
				h.events = append(h.events, "host")
				if requested != domain {
					t.Errorf("another command changed the domain: %q", requested)
				}
				return "host." + domain, domain, nil
			}
			var previous *testReport
			h.inspect = func(_ context.Context, o operationOptions, _ []string, _ []byte) {
				if o.realm != strings.ToUpper(domain) || o.relay != "mailgw."+domain || o.report == nil || o.report == previous ||
					o.tlsTrust.Mode != mail.RootsReplace || len(o.tlsTrust.Certificates) != 1 || len(o.tlsTrust.Allow) != 1 ||
					o.tlsTrust.ExpiredServerCertificateGrace != time.Hour || !o.tlsTrust.InsecureAllowUnverifiableIssuer {
					t.Errorf("execution state was lost or reused: domain=%q realm=%q relay=%q trust=%+v", domain, o.realm, o.relay, o.tlsTrust)
				}
				previous = o.report
			}
			cmd := newCommandWithDependencies(h.deps)
			cmd.SetArgs([]string{"--test", "--domain=" + domain, "--cred-source=ccache", "--tls-ca=" + rootPath, "--tls-ca-mode=replace",
				"--tls-ca-allow-cert-sha256=" + strings.Repeat("a", 64),
				"--insecure-tls-allow-expired-server-cert-for=1h", "--insecure-tls-allow-server-certificate-with-unverifiable-issuer"})
			for range 2 {
				cmd.SetIn(forbiddenReader{})
				cmd.SetErr(io.Discard)
				if err := cmd.ExecuteContext(t.Context()); err != nil {
					t.Fatal(err)
				}
				if h.releases != 1 || h.closes != 1 || !reflect.DeepEqual(h.events, []string{"host", "ad:ccache", "deliver", "release", "close-ad"}) {
					t.Fatalf("execution ownership leaked: %v releases=%d closes=%d", h.events, h.releases, h.closes)
				}
				h.events, h.releases, h.closes = nil, 0, 0
				// Reuse parsed flags; reparsing StringArray arguments appends by design.
				cmd.SetArgs([]string{})
			}
		})
	}
}

func commandCertificateFiles(t *testing.T) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(t.TempDir(), "client.pem"), filepath.Join(t.TempDir(), "client.key")
	for path, data := range map[string][]byte{
		certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPath:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return certPath, keyPath
}

func TestCommandCertificateStageOrderAndOwnership(t *testing.T) {
	for _, auth := range []string{"mtls", "mtls-external"} {
		for _, mode := range []string{"send", "test", "testmail", "owner-error", "delivery-error", "cleanup-warning", "test-cleanup-error"} {
			t.Run(auth+"/"+mode, func(t *testing.T) {
				isolatedSenderConfig(t)
				cert, key := commandCertificateFiles(t)
				h := newCommandHarness(t)
				cause := errors.New("certificate boundary failed")
				args := []string{"--auth=" + auth, "--client-cert=" + cert, "--client-key=" + key,
					"--domain=corp.example", "--from=sender@corp.example", "recipient@corp.example"}
				want := []string{"host", "stdin", "dns-owner", "deliver", "close-dns"}
				wantErr := false
				switch mode {
				case "test", "test-cleanup-error":
					args = append(args[:4], "--test")
					want = []string{"host", "dns-owner", "deliver", "close-dns"}
					if mode == "test-cleanup-error" {
						h.closeErr, wantErr = cause, true
					}
				case "testmail":
					args = append(args, "--testmail")
					want = []string{"host", "dns-owner", "deliver", "close-dns"}
				case "owner-error":
					h.dnsErr, wantErr = cause, true
					want = want[:3]
				case "delivery-error":
					h.deliveryErr, wantErr = errors.Join(cause, mail.ErrRelayUnavailable), true
				case "cleanup-warning":
					h.closeErr = cause
				}
				err := h.execute(t, args...)
				if !reflect.DeepEqual(h.events, want) || h.releases != 0 || h.closes != 0 ||
					(err != nil) != wantErr || (wantErr && !errors.Is(err, cause)) {
					t.Fatalf("events=%v want=%v err=%v", h.events, want, err)
				}
			})
		}
	}
}
