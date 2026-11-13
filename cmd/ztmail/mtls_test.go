package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/ztmail/internal/mail"
)

func TestDNSOwnerCleanupDetachedAndAwaited(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "canceled", true: "expired"}[expired], func(t *testing.T) {
			var ctx context.Context
			var cancel context.CancelFunc
			if expired {
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			cancel()
			cause := errors.New("delayed owner cleanup failed")
			completed := false
			start := time.Now()
			err := closeDNSOwner(ctx, func(cleanup context.Context) error {
				if cleanup.Err() != nil {
					t.Fatalf("cleanup inherited cancellation: %v", cleanup.Err())
				}
				deadline, ok := cleanup.Deadline()
				if !ok || time.Until(deadline) < 4*time.Second || time.Until(deadline) > 5*time.Second {
					t.Fatalf("cleanup deadline=%v, present=%t", deadline, ok)
				}
				time.Sleep(20 * time.Millisecond)
				if cleanup.Err() != nil {
					t.Fatalf("delayed cleanup interrupted: %v", cleanup.Err())
				}
				completed = true
				return cause
			})
			if !completed || !errors.Is(err, cause) || time.Since(start) < 20*time.Millisecond {
				t.Fatalf("cleanup abandoned/lost: completed=%t err=%v elapsed=%s", completed, err, time.Since(start))
			}
		})
	}
}

func TestMTLSCLIExplicitFlagConflictsBeforeInput(t *testing.T) {
	for _, flag := range []string{"--cred-source=auto", "--password-prompt=false", "--realm=EXAMPLE.TEST", "--spn=smtp/relay",
		"--ldap-race-candidates=8", "--no-ldap-race=false", "--keytab=missing", "--ccache=missing", "--principal=user",
		"--ldap-ca=missing", "--sendmail-path=/not/sendmail"} {
		t.Run(flag, func(t *testing.T) {
			command := newCommand()
			command.SetArgs([]string{"--auth=mtls-external", "--client-cert=missing", "--client-key=missing", flag})
			command.SetIn(failingReader{})
			if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "conflicts with explicit") {
				t.Fatalf("conflicting explicit flag reached credential/input work: %v", err)
			}
		})
	}
	for _, args := range [][]string{
		{"--auth=invalid"},
		{"--insecure-tls-allow-expired-server-cert-for=0s"},
		{"--insecure-tls-allow-expired-server-cert-for=-1h"},
		{"--auth=mtls"},
		{"--auth=mtls", "--client-cert=missing"},
		{"--auth=gssapi", "--client-cert=missing", "--client-key=missing"},
		{"--auth=mtls", "--client-cert=missing", "--client-key=missing", "--tls=off"},
		{"--show-default-from", "--auth=mtls", "--client-cert=missing", "--client-key=missing"},
	} {
		command := newCommand()
		command.SetArgs(args)
		command.SetIn(failingReader{})
		if err := command.Execute(); err == nil {
			t.Fatalf("invalid TLS flag combination accepted: %v", args)
		}
	}
}

func TestMTLSNeverUsesNativeFallback(t *testing.T) {
	for _, method := range []string{"mtls", "mtls-external"} {
		for _, failure := range []error{errHostDomainUnavailable, errADCredentialsUnavailable, mail.ErrRelayUnavailable} {
			if shouldFallbackToSendmail(context.Background(), options{authMethod: method}, failure) {
				t.Fatalf("%s credential/relay failure enabled native fallback: %v", method, failure)
			}
		}
	}
}

func TestMTLSSenderRecipientErrorsBeforeDNS(t *testing.T) {
	for _, tt := range []struct {
		from       string
		recipients []string
		testmail   bool
		want       string
	}{
		{"", []string{"recipient@example.test"}, false, "requires -f"},
		{"sender@example.test", nil, false, "requires explicit/header recipients"},
		{"sender@example.test", nil, true, "requires explicit/header recipients"},
		{"<>", []string{"recipient@example.test"}, true, "non-null sender"},
	} {
		err := runCertificateSubmission(context.Background(), options{authMethod: "mtls-external", from: tt.from, testMail: tt.testmail},
			tt.recipients, nil, nil)
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Fatalf("invalid input reached DNS/credentials: %v", err)
		}
	}
}

func TestMTLSClientFileFailureDoesNotProbeCredentialsOrReadInput(t *testing.T) {
	command := newCommand()
	command.SetArgs([]string{"--auth=mtls-external", "--domain=example.test", "--client-cert=" + filepath.Join(t.TempDir(), "missing.pem"),
		"--client-key=missing.key", "--test"})
	command.SetIn(failingReader{})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "read client certificate") ||
		errors.Is(err, errADCredentialsUnavailable) {
		t.Fatalf("mTLS file failure reached AD or input: %v", err)
	}
}
