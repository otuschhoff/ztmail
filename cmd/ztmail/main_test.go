package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("input failed") }

func TestNormalizeArgs(t *testing.T) {
	for _, tt := range []struct{ in, want []string }{
		{[]string{"-oi", "-t"}, []string{"-i", "-t"}},
		{[]string{"-oi", "--", "-oi"}, []string{"-i", "--", "-oi"}},
		{[]string{"--", "-oi"}, []string{"--", "-oi"}},
	} {
		if got := normalizeArgs(tt.in); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("normalizeArgs(%v) = %v; want %v", tt.in, got, tt.want)
		}
	}
}

func TestCommandFlagValidation(t *testing.T) {
	tests := [][]string{
		{"--port", "0"},
		{"--timeout", "0s"},
		{"--tls", "insecure"},
		{"--cred-source", "plain"},
		{"--keytab", "a", "--ccache", "b"},
		{"--cred-source", "keytab"},
		{"--cred-source", "sspi", "--keytab", "a"},
		{"--cred-source", "sspi", "--password-prompt"},
		{"--cred-source", "keytab", "--keytab", "a", "--password-prompt"},
		{"--cred-source", "ccache", "--ccache", "a", "--password-prompt"},
		{"--cred-source", "keytab", "--keytab", "a", "--ccache", "b"},
		{"--krb5-config", "/tmp/krb5.conf"},
		{"--unsupported"},
		{"--ldap-race-candidates", "0"},
		{"--ldap-race-candidates", "-1"},
		{"--ldap-race-candidates", "9"},
		{"--no-ldap-race", "--ldap-race-candidates", "0"},
	}
	for _, args := range tests {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			cmd := newCommand()
			cmd.SetArgs(args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.Execute(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestCommandHelp(t *testing.T) {
	cmd := newCommand()
	cmd.SetArgs([]string{"--help"})
	var output bytes.Buffer
	cmd.SetOut(&output)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "--cred-source") || !strings.Contains(output.String(), "--auth") ||
		!strings.Contains(output.String(), "SMTP authentication: gssapi, mtls") {
		t.Fatalf("incorrect credential flag in help:\n%s", &output)
	}
}

func TestCredentialSourceFlag(t *testing.T) {
	for _, source := range []string{"auto", "keytab", "ccache", "sspi"} {
		cmd := newCommand()
		if err := cmd.ParseFlags([]string{"--cred-source", source}); err != nil {
			t.Fatal(err)
		}
		if got, err := cmd.Flags().GetString("cred-source"); err != nil || got != source {
			t.Fatalf("source=%q: got %q, err=%v", source, got, err)
		}
	}
	cmd := newCommand()
	if got, err := cmd.Flags().GetString("cred-source"); err != nil || got != "auto" {
		t.Fatalf("default source=%q, err=%v", got, err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--cred-source", "plain"}, "--cred-source must be auto, keytab, ccache, or sspi"},
		{[]string{"--cred-source", "keytab"}, "--cred-source keytab requires --keytab"},
		{[]string{"--auth", "auto"}, "--auth must be gssapi, mtls, or mtls-external"},
	} {
		cmd := newCommand()
		cmd.SetArgs(tc.args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: expected %q, got %v", tc.args, tc.want, err)
		}
	}
}

func TestLDAPRaceFlags(t *testing.T) {
	for _, tt := range []struct {
		args       []string
		candidates int
		disabled   bool
	}{
		{nil, 8, false},
		{[]string{"--ldap-race-candidates", "1"}, 1, false},
		{[]string{"--ldap-race-candidates", "8"}, 8, false},
		{[]string{"--no-ldap-race"}, 8, true},
		{[]string{"--no-ldap-race", "--ldap-race-candidates", "1"}, 1, true},
	} {
		cmd := newCommand()
		if err := cmd.ParseFlags(tt.args); err != nil {
			t.Fatal(err)
		}
		candidates, err := cmd.Flags().GetInt("ldap-race-candidates")
		if err != nil || candidates != tt.candidates {
			t.Fatalf("%v: candidates=%d err=%v", tt.args, candidates, err)
		}
		disabled, err := cmd.Flags().GetBool("no-ldap-race")
		if err != nil || disabled != tt.disabled {
			t.Fatalf("%v: disabled=%t err=%v", tt.args, disabled, err)
		}
		if err := validateOptions(options{port: 25, timeout: time.Second, auth: "auto",
			tlsMode: "required", ldapRaceCandidates: candidates, noLDAPRace: disabled}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestValidOptions(t *testing.T) {
	if err := validateOptions(options{port: 25, timeout: time.Second, auth: "auto", tlsMode: "required", ldapRaceCandidates: 8}); err != nil {
		t.Fatal(err)
	}

}

func TestPasswordFallbackAllowsConfiguredKeytabAndCache(t *testing.T) {
	o := options{port: 25, timeout: time.Second, auth: "auto", tlsMode: "required", ldapRaceCandidates: 8,
		keytab: "keytab", ccache: "cache", passwordPrompt: true}
	if err := validateOptions(o); err != nil {
		t.Fatal(err)
	}
	o.passwordPrompt = false
	if err := validateOptions(o); err == nil {
		t.Fatal("source exclusivity must remain unchanged without opt-in")
	}
}

func TestDNSName(t *testing.T) {
	for _, tt := range []struct {
		input, want string
		fail        bool
	}{
		{"HOST.Example.COM.", "host.example.com", false},
		{"host", "host", false},
		{"", "", true},
		{"127.0.0.1", "", true},
		{"::1", "", true},
		{"bad..example.com", "", true},
		{"-bad.example.com", "", true},
		{"bad-.example.com", "", true},
		{"bad/example.com", "", true},
		{"mail.example.com:25", "", true},
		{"bad\n.example.com", "", true},
	} {
		got, err := dnsName(tt.input)
		if (err != nil) != tt.fail || got != tt.want {
			t.Errorf("%q = %q, %v; want %q, fail=%v", tt.input, got, err, tt.want, tt.fail)
		}
	}
}

func TestDomainOverride(t *testing.T) {
	host, domain, err := discoverHost(context.Background(), "Example.COM.")
	if err != nil || host == "" || domain != "example.com" {
		t.Fatalf("host=%q domain=%q err=%v", host, domain, err)
	}
}

func TestHostDomain(t *testing.T) {
	for host, want := range map[string]string{
		"host.example.com": "example.com", "host.sub.example.com": "sub.example.com",
		"host": "", "host.localdomain": "", "host.localhost": "",
	} {
		if got := hostDomain(host); got != want {
			t.Errorf("%s: got %q; want %q", host, got, want)
		}
	}
}
