package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/kerberos"
)

type fakePasswordTerminal struct {
	input          *strings.Reader
	output         bytes.Buffer
	password       []byte
	passwordErr    error
	writeErr       error
	onPasswordRead func()
	passwordReads  int
	principalReads int
}

func (f *fakePasswordTerminal) Read(p []byte) (int, error) {
	f.principalReads++
	return f.input.Read(p)
}
func (f *fakePasswordTerminal) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.output.Write(p)
}
func (f *fakePasswordTerminal) ReadPassword() ([]byte, error) {
	f.passwordReads++
	if f.onPasswordRead != nil {
		f.onPasswordRead()
	}
	return f.password, f.passwordErr
}
func (f *fakePasswordTerminal) Close() error { return nil }

func TestPasswordPromptPrincipalSelection(t *testing.T) {
	for _, tt := range []struct {
		name, input, guess, want string
		pinned                   bool
	}{
		{"accept-guess", "\n", "alice@EXAMPLE.COM", "alice@EXAMPLE.COM", false},
		{"accept-guess-crlf", "\r\n", "alice@EXAMPLE.COM", "alice@EXAMPLE.COM", false},
		{"replacement", "bob@example.com\n", "alice@EXAMPLE.COM", "bob@EXAMPLE.COM", false},
		{"unqualified-replacement", "bob\n", "alice@EXAMPLE.COM", "bob@EXAMPLE.COM", false},
		{"explicit-pinned", "", "explicit@EXAMPLE.COM", "explicit@EXAMPLE.COM", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			terminal := &fakePasswordTerminal{input: strings.NewReader(tt.input), password: []byte("synthetic-secret")}
			principal, password, err := readPasswordCredentials(context.Background(), terminal, tt.guess, tt.pinned, "EXAMPLE.COM", nil)
			defer clear(password)
			if err != nil || principal != tt.want || string(password) != "synthetic-secret" {
				t.Fatalf("principal=%q err=%v", principal, err)
			}
			if !strings.Contains(terminal.output.String(), tt.guess) || strings.Contains(terminal.output.String(), "synthetic-secret") {
				t.Fatal("guessed principal was not shown or password was printed")
			}
			if !strings.Contains(terminal.output.String(), "No usable existing credentials. Signing in with a password.") ||
				strings.Contains(terminal.output.String(), "TGT") ||
				strings.Contains(terminal.output.String(), "type a replacement") {
				t.Fatalf("unexpected prompt wording: %s", &terminal.output)
			}
			if tt.pinned && terminal.principalReads != 0 {
				t.Fatal("explicit principal must not allow interactive replacement")
			}
		})
	}
}

func TestPasswordPromptErrors(t *testing.T) {
	for _, tt := range []struct {
		name, line string
		password   []byte
		err        error
	}{
		{"principal-eof", "", []byte("synthetic"), nil},
		{"wrong-realm", "bob@OTHER.COM\n", []byte("synthetic"), nil},
		{"invalid-principal", "bad user\n", []byte("synthetic"), nil},
		{"password-empty", "\n", nil, nil},
		{"password-eof", "\n", []byte("partial-secret"), io.EOF},
	} {
		t.Run(tt.name, func(t *testing.T) {
			terminal := &fakePasswordTerminal{input: strings.NewReader(tt.line), password: tt.password, passwordErr: tt.err}
			_, password, err := readPasswordCredentials(context.Background(), terminal, "alice@EXAMPLE.COM", false, "EXAMPLE.COM", nil)
			if err == nil || password != nil {
				t.Fatal("invalid prompt input accepted")
			}
			if strings.Contains(err.Error(), "partial-secret") {
				t.Fatal("password leaked into error")
			}
			if terminal.passwordReads > 0 && !bytes.Equal(terminal.password, make([]byte, len(terminal.password))) {
				t.Fatal("partial password was not cleared on read failure")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	terminal := &fakePasswordTerminal{input: strings.NewReader("\n"), password: []byte("synthetic")}
	if _, _, err := readPasswordCredentials(ctx, terminal, "alice@EXAMPLE.COM", false, "EXAMPLE.COM", nil); !errors.Is(err, context.Canceled) ||
		terminal.principalReads != 0 || terminal.passwordReads != 0 {
		t.Fatal("canceled context performed prompt work")
	}
}

func TestPasswordPromptExecutionRuntimeReporting(t *testing.T) {
	for _, test := range []struct {
		name, input               string
		passwordError, writeError error
		canceled                  bool
	}{
		{name: "success", input: "\n"},
		{name: "principal-eof", input: ""},
		{name: "password-error", input: "\n", passwordError: io.EOF},
		{name: "terminal-write-error", input: "\n", writeError: errors.New("terminal output failed")},
		{name: "already-canceled", input: "\n", canceled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			report := newTestReport(&output, false)
			terminal := &fakePasswordTerminal{input: strings.NewReader(test.input), password: []byte("synthetic-secret"),
				passwordErr: test.passwordError, writeErr: test.writeError}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.canceled {
				cancel()
			}
			_, password, err := readPasswordCredentials(ctx, terminal, "alice@EXAMPLE.COM", false, "EXAMPLE.COM", report)
			clear(password)
			report.Finish(&err)
			if strings.Contains(output.String(), "Execution runtime") != (terminal.passwordReads > 0) {
				t.Errorf("execution runtime did not reflect actual password prompting:\n%s", output.String())
			}
			if strings.Contains(output.String(), "synthetic-secret") {
				t.Fatal("password leaked into report")
			}
		})
	}
}

func TestGuessedPrincipal(t *testing.T) {
	for _, username := range []string{"alice", `CORP\alice`, "alice@corp.example"} {
		if got := guessedPrincipal(username, "example.com"); got != "alice@EXAMPLE.COM" {
			t.Fatalf("guess(%q)=%q", username, got)
		}
	}
}

func TestPasswordPromptWriteAndCancellationErrors(t *testing.T) {
	writeErr := errors.New("terminal output failed")
	terminal := &fakePasswordTerminal{input: strings.NewReader("\n"), writeErr: writeErr}
	if _, _, err := readPasswordCredentials(context.Background(), terminal, "alice@EXAMPLE.COM", false, "EXAMPLE.COM", nil); !errors.Is(err, writeErr) {
		t.Fatalf("lost terminal output error: %v", err)
	}
	if terminal.passwordReads != 0 || terminal.principalReads != 0 {
		t.Fatal("read input after prompt write failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	terminal = &fakePasswordTerminal{input: strings.NewReader("\n"), password: []byte("synthetic"), onPasswordRead: cancel}
	_, password, err := readPasswordCredentials(ctx, terminal, "alice@EXAMPLE.COM", false, "EXAMPLE.COM", nil)
	if !errors.Is(err, context.Canceled) || password != nil || !bytes.Equal(terminal.password, make([]byte, len(terminal.password))) {
		t.Fatal("password retained after cancellation")
	}
}

func TestPrincipalInputLimit(t *testing.T) {
	if _, err := readPrincipalLine(context.Background(), strings.NewReader(strings.Repeat("x", 1025)+"\n")); err == nil {
		t.Fatal("oversized principal accepted")
	}
}

func TestCredentialFallbackIsOptIn(t *testing.T) {
	calls := 0
	o := options{auth: "auto", keytab: "keytab"}
	_, err := chooseADCredentials(context.Background(), o, func(_ context.Context, got options) (*adSession, error) {
		calls++
		if got.auth != "auto" {
			t.Fatal("default source policy changed")
		}
		return nil, errors.New("source failed")
	}, func(context.Context, options) (*adSession, error) {
		t.Fatal("password prompt was used without opt-in")
		return nil, nil
	})
	if err == nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestPasswordFallbackRunsLast(t *testing.T) {
	var attempts []string
	o := options{auth: "auto", keytab: "keytab", ccache: "cache", principal: "alice@EXAMPLE.COM", passwordPrompt: true}
	sourceFailure := errors.New("source rejected")
	selected := &adSession{}
	session, err := chooseADCredentials(context.Background(), o, func(_ context.Context, attempt options) (*adSession, error) {
		attempts = append(attempts, attempt.auth)
		if attempt.principal != o.principal {
			t.Fatal("explicit principal constraint lost")
		}
		if attempt.auth == "keytab" && attempt.ccache != "" {
			t.Fatal("cache leaked into keytab attempt")
		}
		if attempt.auth == "ccache" && attempt.keytab != "" {
			t.Fatal("keytab leaked into cache attempt")
		}
		return nil, sourceFailure
	}, func(_ context.Context, got options) (*adSession, error) {
		attempts = append(attempts, "password")
		if got.principal != o.principal {
			t.Fatal("password fallback lost explicit principal")
		}
		return selected, nil
	})
	want := []string{"keytab", "ccache"}
	if runtime.GOOS == "windows" {
		want = append(want, "sspi")
	}
	want = append(want, "password")
	if err != nil || session != selected || !reflect.DeepEqual(attempts, want) || len(session.failures) != len(want)-1 {
		t.Fatalf("attempts=%v failures=%v err=%v", attempts, session.failures, err)
	}
}

func TestEarlierCredentialSuccessSkipsPassword(t *testing.T) {
	selected := &adSession{}
	session, err := chooseADCredentials(context.Background(), options{auth: "auto", passwordPrompt: true},
		func(context.Context, options) (*adSession, error) { return selected, nil },
		func(context.Context, options) (*adSession, error) {
			t.Fatal("unnecessary password prompt")
			return nil, nil
		})
	if err != nil || session != selected {
		t.Fatalf("session=%v err=%v", session, err)
	}
}

func TestFatalCredentialFailureStopsPasswordFallback(t *testing.T) {
	for _, failure := range []error{context.Canceled, kerberos.ErrClosed, kerberos.ErrCapacity, errADCleanup} {
		_, err := chooseADCredentials(context.Background(), options{auth: "auto", passwordPrompt: true},
			func(context.Context, options) (*adSession, error) { return nil, failure },
			func(context.Context, options) (*adSession, error) {
				t.Fatal("prompt after fatal error")
				return nil, nil
			})
		if !errors.Is(err, failure) {
			t.Fatalf("lost error: %v", err)
		}
	}
}

func TestCredentialStageTimeoutCanFallBack(t *testing.T) {
	prompted := false
	selected := &adSession{}
	session, err := chooseADCredentials(context.Background(), options{auth: "auto", passwordPrompt: true},
		func(context.Context, options) (*adSession, error) { return nil, context.DeadlineExceeded },
		func(context.Context, options) (*adSession, error) { prompted = true; return selected, nil })
	if err != nil || session != selected || !prompted {
		t.Fatalf("stage timeout prevented fallback: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = chooseADCredentials(ctx, options{auth: "auto", passwordPrompt: true},
		func(context.Context, options) (*adSession, error) { cancel(); return nil, context.Canceled },
		func(context.Context, options) (*adSession, error) {
			t.Fatal("prompt after parent cancellation")
			return nil, nil
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost parent cancellation: %v", err)
	}
}

func TestPasswordFallbackPreservesErrors(t *testing.T) {
	sourceErr, passwordErr := errors.New("cache rejected"), errors.New("password rejected")
	_, err := chooseADCredentials(context.Background(), options{auth: "auto", passwordPrompt: true},
		func(context.Context, options) (*adSession, error) { return nil, sourceErr },
		func(context.Context, options) (*adSession, error) { return nil, passwordErr })
	if !errors.Is(err, sourceErr) || !errors.Is(err, passwordErr) {
		t.Fatalf("lost fallback causes: %v", err)
	}
	if !errors.Is(err, errADPasswordFailure) || errors.Is(err, errADNonCredentialFailure) {
		t.Fatalf("password failure mislabeled as configuration/post-acquisition failure: %v", err)
	}
	if shouldFallbackToSendmail(context.Background(), options{}, errors.Join(errADCredentialsUnavailable, err)) {
		t.Fatal("password sign-in failure allowed native sendmail fallback")
	}
}

func TestPasswordSDKConfigurationDoesNotConsultFailedCache(t *testing.T) {
	t.Setenv("KRB5CCNAME", "KCM:unsupported")
	t.Setenv("KRB5_CONFIG", "/does-not-exist/krb5.conf")
	o := options{auth: "auto", domain: "corp.example", realm: "CORP.EXAMPLE", dnsProbeZone: "example.com"}
	credentials := kerberos.Options{Source: kerberos.SourcePassword, Principal: "alice@CORP.EXAMPLE", Realm: o.realm, Password: "synthetic"}
	settings, err := adOptionsForCredentials(o, credentials)
	if err != nil {
		t.Fatal(err)
	}
	client, err := adclient.NewAD(settings)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
