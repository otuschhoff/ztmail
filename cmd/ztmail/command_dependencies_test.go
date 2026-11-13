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
	inspect                                     func(context.Context, options, []string, []byte)
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
	h.deps.attemptAD = func(ctx context.Context, o options, settings adclient.ADOptions) (*adSession, error) {
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
		return &adSession{
			identity: kerberos.Identity{Principal: "alice@CORP.EXAMPLE", Realm: "CORP.EXAMPLE", Source: settings.Credentials.Source},
			mail:     "alice@corp.example", hostWithoutMail: h.hostWithoutMail, report: o.report,
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
	h.deps.deliver = func(ctx context.Context, o options, recipients []string, message []byte, _ submissionBackend, _ io.Writer) error {
		h.events = append(h.events, "deliver")
		if h.closes != 0 || h.dnsCloses != 0 {
			t.Error("owner closed before delivery")
		}
		if h.inspect != nil {
			h.inspect(ctx, o, recipients, message)
		}
		return h.deliveryErr
	}
	h.deps.fallback = func(_ context.Context, _ options, _ []string, _ []byte, _ string, _ error, _ io.Writer) error {
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
			h.inspect = func(_ context.Context, o options, recipients []string, message []byte) {
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
				h.deps.attemptAD = func(ctx context.Context, o options, settings adclient.ADOptions) (*adSession, error) {
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
	for _, mode := range []string{"send", "lookup", "terminal-close-error", "prompt-error", "password-error", "owner-close-error"} {
		t.Run(mode, func(t *testing.T) {
			isolatedSenderConfig(t)
			h := newCommandHarness(t)
			h.sourceErr = errADCredentialsUnavailable
			cause := errors.New("password boundary failed")
			args := []string{"--password-prompt", "--domain=corp.example", "--from=sender@corp.example", "recipient@corp.example"}
			want := []string{"host", "stdin", "ad:ccache", "user", "terminal", "close-terminal", "ad:password", "deliver", "release", "close-ad"}
			wantErr := false
			switch mode {
			case "lookup":
				args = []string{"--set-default-from-ad", "--domain=corp.example"}
				want = []string{"host", "ad:ccache", "user", "terminal", "close-terminal", "ad:password", "release", "close-ad"}
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
				index := 0
				for want[index] != "ad:ccache" {
					index++
				}
				want = append(want[:index+1], append([]string{"ad:sspi"}, want[index+1:]...)...)
			}
			err := h.execute(t, args...)
			if !reflect.DeepEqual(h.events, want) || h.terminals != 1 || h.releases != h.closes ||
				(err != nil) != wantErr || (wantErr && !errors.Is(err, cause)) {
				t.Fatalf("events=%v want=%v terminal-closes=%d err=%v", h.events, want, h.terminals, err)
			}
			for _, b := range h.terminal.password {
				if b != 0 {
					t.Fatal("password bytes not cleared")
				}
			}
			address, readErr := readDefaultSender()
			if readErr != nil || (address != "") != (mode == "lookup") {
				t.Fatalf("persisted address=%q err=%v", address, readErr)
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
