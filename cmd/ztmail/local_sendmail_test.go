package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/ztmail/internal/mail"
)

func fakeLocalSendmail(t *testing.T) (executable, argsPath, messagePath string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("native fallback is Linux-only")
	}
	dir := t.TempDir()
	t.Setenv(nativeFallbackEnvironment, "")
	executable = filepath.Join(dir, "sendmail")
	argsPath, messagePath = filepath.Join(dir, "args"), filepath.Join(dir, "message")
	t.Setenv("ZTMAIL_TEST_ARGS", argsPath)
	t.Setenv("ZTMAIL_TEST_MESSAGE", messagePath)
	script := "#!/bin/sh\n[ \"$ZTMAIL_SENDMAIL_FALLBACK\" = 1 ] || exit 99\nprintf '%s\\n' \"$@\" > \"$ZTMAIL_TEST_ARGS\"\ncat > \"$ZTMAIL_TEST_MESSAGE\"\n"
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return
}

func TestSendmailFallbackEligibility(t *testing.T) {
	t.Setenv(nativeFallbackEnvironment, "")
	ctx := context.Background()
	eligible := runtime.GOOS == "linux"
	for _, tc := range []struct {
		name string
		o    options
		err  error
		want bool
	}{
		{"credentials", options{}, fmt.Errorf("missing cache: %w", errADCredentialsUnavailable), eligible},
		{"domain", options{}, errHostDomainUnavailable, eligible},
		{"relay", options{}, mail.ErrRelayUnavailable, eligible},
		{"stage deadline", options{}, errors.Join(errADCredentialsUnavailable, context.DeadlineExceeded), eligible},
		{"opt out", options{noSendmailFallback: true}, errADCredentialsUnavailable, false},
		{"test", options{testMode: true}, mail.ErrRelayUnavailable, false},
		{"testmail", options{testMail: true}, mail.ErrRelayUnavailable, false},
		{"management", options{setDefaultFromAD: true}, errADCredentialsUnavailable, false},
		{"uncertain", options{}, errors.Join(mail.ErrRelayUnavailable, mail.ErrDeliveryUncertain), false},
		{"cleanup", options{}, errors.Join(errADCredentialsUnavailable, errADCleanup), false},
		{"closed", options{}, errors.Join(errADCredentialsUnavailable, kerberos.ErrClosed), false},
		{"capacity", options{}, errors.Join(errADCredentialsUnavailable, kerberos.ErrCapacity), false},
		{"credentials changed", options{}, errors.Join(errADCredentialsUnavailable, kerberos.ErrCredentialsChanged), false},
		{"canceled", options{}, errors.Join(errADCredentialsUnavailable, context.Canceled), false},
		{"mixed credential and LDAP failure", options{}, errors.Join(errADCredentialsUnavailable, errADNonCredentialFailure), false},
		{"TLS rejection", options{}, errors.New("TLS certificate rejected"), false},
		{"SMTP auth rejection", options{}, errors.New("SMTP AUTH 535 rejected"), false},
		{"MAIL rejection", options{}, errors.New("SMTP MAIL FROM rejected"), false},
		{"RCPT rejection", options{}, errors.New("SMTP RCPT TO rejected"), false},
		{"DATA rejection", options{}, errors.New("SMTP DATA rejected"), false},
		{"success", options{}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldFallbackToSendmail(ctx, tc.o, tc.err); got != tc.want {
				t.Fatalf("fallback=%v, want %v: %v", got, tc.want, tc.err)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if shouldFallbackToSendmail(canceled, options{}, mail.ErrRelayUnavailable) {
		t.Fatal("caller cancellation must never fall back")
	}
	expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer cancel()
	if shouldFallbackToSendmail(expired, options{}, mail.ErrRelayUnavailable) {
		t.Fatal("caller deadline must never fall back")
	}
	t.Setenv(nativeFallbackEnvironment, "1")
	if shouldFallbackToSendmail(ctx, options{}, mail.ErrRelayUnavailable) {
		t.Fatal("native child must not recursively fall back, even from another binary copy")
	}
}

func TestSendmailFallbackPreservesOrOverridesSender(t *testing.T) {
	executable, argsPath, messagePath := fakeLocalSendmail(t)
	original := []byte("From: Original <original@example.com>\r\nSender: original@example.com\r\nSubject: test\r\n\r\nbody\r\n.dot\r\n.\r\n")
	recipients := []string{"one@example.com", "two@example.com"}
	for _, from := range []string{"", "<>", "saved@example.com"} {
		var log bytes.Buffer
		o := options{sendmailPath: executable, timeout: time.Second, domain: "example.com"}
		if err := sendmailFallback(context.Background(), o, recipients, original, from, errADCredentialsUnavailable, &log); err != nil {
			t.Fatal(err)
		}
		gotArgs, err := os.ReadFile(argsPath)
		if err != nil {
			t.Fatal(err)
		}
		wantArgs := []string{"-i"}
		if from != "" {
			wantArgs = append(wantArgs, "-f", from)
		}
		wantArgs = append(wantArgs, "--", recipients[0], recipients[1])
		if got := strings.Split(strings.TrimSuffix(string(gotArgs), "\n"), "\n"); !reflect.DeepEqual(got, wantArgs) {
			t.Fatalf("from=%q: args=%q, want=%q", from, got, wantArgs)
		}
		gotMessage, err := os.ReadFile(messagePath)
		if err != nil {
			t.Fatal(err)
		}
		wantMessage := original
		if from != "" && from != "<>" {
			wantMessage, _, err = applySender(original, from, "", o.domain)
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(gotMessage, wantMessage) {
			t.Fatalf("from=%q: message changed unexpectedly:\n%s", from, gotMessage)
		}
		if !strings.Contains(log.String(), "Warning:") || !strings.Contains(log.String(), executable) {
			t.Fatalf("fallback was not reported: %q", &log)
		}
	}
}

func TestCommandMissingCredentialsUsesOnlyFakeSendmail(t *testing.T) {
	executable, argsPath, messagePath := fakeLocalSendmail(t)
	configPath := isolatedSenderConfig(t)
	for _, source := range []string{"keytab", "ccache"} {
		for _, sender := range []string{"original", "saved", "explicit", "null"} {
			t.Run(source+"/"+sender, func(t *testing.T) {
				if err := os.Remove(configPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				args := []string{"--domain", "corp.example.com", "--hostname", "host.corp.example.com",
					"--cred-source", source, "--" + source, filepath.Join(t.TempDir(), "missing"),
					"--sendmail-path", executable, "-i", "-t"}
				from := "original@example.com"
				if sender != "original" {
					if _, err := writeDefaultSender("saved@example.com"); err != nil {
						t.Fatal(err)
					}
					from = "saved@example.com"
				}
				if sender == "explicit" {
					args = append(args, "-f", "explicit@example.com")
					from = "explicit@example.com"
				} else if sender == "null" {
					args = append(args, "-f", "<>")
					from = "original@example.com"
				}
				cmd := newCommand()
				cmd.SetArgs(args)
				cmd.SetIn(strings.NewReader("From: original@example.com\nSender: original@example.com\nTo: to@example.com\nBcc: blind@example.com\nSubject: fallback\n\nbody\n.\n"))
				var log bytes.Buffer
				cmd.SetErr(&log)
				if err := cmd.Execute(); err != nil {
					t.Fatalf("command fallback: %v; log=%s", err, &log)
				}
				data, err := os.ReadFile(messagePath)
				headerFrom := from
				if sender == "saved" || sender == "explicit" {
					headerFrom = "<" + from + ">"
				}
				if err != nil || !bytes.Contains(data, []byte("From: "+headerFrom+"\n")) ||
					!bytes.Contains(data, []byte("Sender: "+headerFrom+"\n")) ||
					bytes.Contains(data, []byte("Bcc:")) || !bytes.HasSuffix(data, []byte("\n.\n")) {
					t.Fatalf("native message=%q, err=%v", data, err)
				}
				captured, err := os.ReadFile(argsPath)
				if err != nil || !bytes.Contains(captured, []byte("--\nto@example.com\nblind@example.com\n")) {
					t.Fatalf("native recipients=%q, err=%v", captured, err)
				}
			})
		}
	}
}

func TestSendmailPathRejectsSelfAndNonExecutable(t *testing.T) {
	executable, _, _ := fakeLocalSendmail(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "sendmail")
	if err := os.Symlink(self, link); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{self, link, filepath.Dir(executable), filepath.Join(t.TempDir(), "missing")} {
		if path, err := findLocalSendmail([]string{candidate}, self); err == nil {
			t.Fatalf("unsafe candidate %q accepted as %q", candidate, path)
		}
	}
	if path, err := findLocalSendmail([]string{link, executable}, self); err != nil || path != executable {
		t.Fatalf("did not skip recursive path: %q, %v", path, err)
	}
	if err := os.Chmod(executable, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := localSendmailPath(executable); err == nil {
		t.Fatal("non-executable file accepted")
	}
}

func TestNativeSubmissionFailureSafety(t *testing.T) {
	executable, argsPath, _ := fakeLocalSendmail(t)
	ctx := context.Background()
	for _, recipients := range [][]string{nil, {"/tmp/mail"}, {"|command@example.com"}, {":include:file@example.com"}, {"x\r\ninjected@example.com"}} {
		if err := submitLocalSendmail(ctx, executable, "", recipients, []byte("Subject: test\n\nbody\n"), io.Discard); err == nil {
			t.Fatalf("unsafe recipients accepted: %q", recipients)
		}
	}
	if _, err := os.Stat(argsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sendmail started for invalid recipients: %v", err)
	}
	if err := submitLocalSendmail(ctx, executable+"missing", "", []string{"root"}, nil, io.Discard); err == nil || errors.Is(err, mail.ErrDeliveryUncertain) {
		t.Fatalf("start failure must be definite: %v", err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 75\n"), 0700); err != nil {
		t.Fatal(err)
	}
	o := options{sendmailPath: executable, timeout: time.Second}
	err := sendmailFallback(ctx, o, []string{"root"}, []byte("Subject: test\n\nbody\n"), "", errADCredentialsUnavailable, io.Discard)
	if !errors.Is(err, errADCredentialsUnavailable) || !errors.Is(err, mail.ErrDeliveryUncertain) {
		t.Fatalf("native failure must retain original error and uncertainty: %v", err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexec /bin/sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	expiring, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = submitLocalSendmail(expiring, executable, "", []string{"root"}, nil, io.Discard)
	if !errors.Is(err, mail.ErrDeliveryUncertain) || !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 2*time.Second {
		t.Fatalf("native timeout not bounded/uncertain: %v (%s)", err, time.Since(start))
	}
}

func TestFallbackLoggingFailurePreventsSubmission(t *testing.T) {
	executable, argsPath, _ := fakeLocalSendmail(t)
	logErr := errors.New("log writer failed")
	o := options{sendmailPath: executable, timeout: time.Second}
	err := sendmailFallback(context.Background(), o, []string{"root"}, nil, "", errADCredentialsUnavailable, failedReportWriter{err: logErr})
	if !errors.Is(err, logErr) || !errors.Is(err, errADCredentialsUnavailable) {
		t.Fatalf("logging/original error lost: %v", err)
	}
	if _, err := os.Stat(argsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("native process started despite logging failure: %v", err)
	}
}

func TestForbiddenFallbackNeverStartsFakeSendmail(t *testing.T) {
	executable, argsPath, _ := fakeLocalSendmail(t)
	for _, tc := range []struct {
		o     options
		cause error
	}{
		{options{noSendmailFallback: true}, errADCredentialsUnavailable},
		{options{testMode: true}, mail.ErrRelayUnavailable},
		{options{testMail: true}, mail.ErrRelayUnavailable},
		{options{}, errors.New("SMTP authentication rejected")},
		{options{}, errors.Join(mail.ErrRelayUnavailable, mail.ErrDeliveryUncertain)},
		{options{}, errors.Join(errADCredentialsUnavailable, errADNonCredentialFailure)},
		{options{}, errors.Join(mail.ErrRelayUnavailable, errADCleanup)},
	} {
		tc.o.sendmailPath, tc.o.timeout = executable, time.Second
		if err := sendmailFallback(context.Background(), tc.o, []string{"root"}, nil, "", tc.cause, io.Discard); err == nil {
			t.Fatalf("forbidden fallback succeeded: %v", tc.cause)
		}
	}
	if _, err := os.Stat(argsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("forbidden fallback started native executable: %v", err)
	}
}
