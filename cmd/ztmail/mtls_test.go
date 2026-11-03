package main

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otuschhoff/ztmail/internal/mail"
)

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
