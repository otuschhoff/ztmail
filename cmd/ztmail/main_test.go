package main

import (
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
		{"--auth", "plain"},
		{"--keytab", "a", "--ccache", "b"},
		{"--auth", "keytab"},
		{"--auth", "sspi", "--keytab", "a"},
		{"--auth", "sspi", "--password-prompt"},
		{"--auth", "keytab", "--keytab", "a", "--password-prompt"},
		{"--auth", "ccache", "--ccache", "a", "--password-prompt"},
		{"--auth", "keytab", "--keytab", "a", "--ccache", "b"},
		{"--krb5-config", "/tmp/krb5.conf"},
		{"--unsupported"},
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
	cmd.SetOut(io.Discard)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestValidOptions(t *testing.T) {
	if err := validateOptions(options{port: 25, timeout: time.Second, auth: "auto", tlsMode: "required"}); err != nil {
		t.Fatal(err)
	}

}

func TestPasswordFallbackAllowsConfiguredKeytabAndCache(t *testing.T) {
	o := options{port: 25, timeout: time.Second, auth: "auto", tlsMode: "required",
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
