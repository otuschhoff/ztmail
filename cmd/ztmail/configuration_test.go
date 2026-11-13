package main

import (
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

type countedErrorReader struct{ calls int }

func (r *countedErrorReader) Read([]byte) (int, error) {
	r.calls++
	return 0, errors.New("message input must not precede DNS validation")
}

func TestInvalidDNSBeforeAllCommandEffects(t *testing.T) {
	for _, mode := range []string{"send", "test", "testmail", "default-ad", "mtls", "mtls-external"} {
		t.Run(mode, func(t *testing.T) {
			isolatedSenderConfig(t)
			for _, value := range []string{"not-an-IP", "0.0.0.0", "ff02::1", "127.0.0.1:0"} {
				t.Run(value, func(t *testing.T) {
					h := newCommandHarness(t)
					args := []string{"--domain=corp.example", "--dns-server=" + value}
					switch mode {
					case "test":
						args = append(args, "--test")
					case "testmail":
						args = append(args, "--testmail")
					case "default-ad":
						args = append(args, "--set-default-from-ad")
					case "mtls", "mtls-external":
						cert, key := commandCertificateFiles(t)
						args = append(args, "--auth="+mode, "--client-cert="+cert, "--client-key="+key)
					}
					cmd := newCommandWithDependencies(h.deps)
					input := &countedErrorReader{}
					cmd.SetArgs(args)
					cmd.SetIn(input)
					cmd.SetOut(io.Discard)
					cmd.SetErr(io.Discard)
					err := cmd.ExecuteContext(t.Context())
					if err == nil || !strings.Contains(err.Error(), "--dns-server") || input.calls != 0 || len(h.events) != 0 {
						t.Fatalf("invalid DNS reached effects: err=%v reads=%d events=%v", err, input.calls, h.events)
					}
				})
			}
		})
	}
}

func TestUnusedDNSDoesNotChangeLocalManagement(t *testing.T) {
	for _, action := range []string{"--show-default-from", "--set-default-from=saved@corp.example", "--unset-default-from"} {
		t.Run(action, func(t *testing.T) {
			isolatedSenderConfig(t)
			h := newCommandHarness(t)
			cmd := newCommandWithDependencies(h.deps)
			cmd.SetArgs([]string{action, "--dns-server=not-an-IP"})
			cmd.SetIn(forbiddenReader{})
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			if err := cmd.ExecuteContext(t.Context()); err != nil || len(h.events) != 0 {
				t.Fatalf("unused AD configuration changed local-only action: %v events=%v", err, h.events)
			}
		})
	}
}

func TestResolveTarget(t *testing.T) {
	for _, tc := range []struct {
		name                                              string
		input                                             options
		wantRealm, wantRelay, wantHello, wantSPN, wantErr string
	}{
		{name: "gssapi defaults", input: options{authMethod: "gssapi"},
			wantRealm: "CORP.EXAMPLE", wantRelay: "mailgw.corp.example", wantHello: "host.corp.example", wantSPN: "smtp/mailgw.corp.example"},
		{name: "certificate has no Kerberos defaults", input: options{authMethod: "mtls"},
			wantRelay: "mailgw.corp.example", wantHello: "host.corp.example"},
		{name: "explicit target", input: options{authMethod: "gssapi", realm: "OTHER.EXAMPLE", relay: "Relay.Example.", hello: "Hello.Example.", spn: "smtp/custom"},
			wantRealm: "OTHER.EXAMPLE", wantRelay: "relay.example", wantHello: "hello.example", wantSPN: "smtp/custom"},
		{name: "realm", input: options{realm: "bad realm"}, wantErr: "invalid Kerberos realm"},
		{name: "relay", input: options{relay: "bad/relay"}, wantErr: "invalid --relay"},
		{name: "hello", input: options{hello: "bad/hello"}, wantErr: "invalid --hostname"},
		{name: "spn", input: options{spn: "smtp/relay\r\n"}, wantErr: "invalid service principal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.input
			got, err := resolveTarget(tc.input, "host.corp.example", "corp.example")
			if !reflect.DeepEqual(tc.input, original) {
				t.Fatal("mutated input options")
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %v want %s", err, tc.wantErr)
				}
				return
			}
			if err != nil || got.realm != tc.wantRealm || got.relay != tc.wantRelay || got.hello != tc.wantHello ||
				got.spn != tc.wantSPN || got.domain != "corp.example" {
				t.Fatalf("target=%+v err=%v", got, err)
			}
		})
	}
}

func TestParseDNSServers(t *testing.T) {
	for _, tc := range []struct {
		name        string
		input, want []string
	}{
		{name: "default"},
		{name: "ipv4", input: []string{"192.0.2.1"}, want: []string{"192.0.2.1:53"}},
		{name: "ipv6", input: []string{"2001:db8::1"}, want: []string{"[2001:db8::1]:53"}},
		{name: "explicit ports and order", input: []string{"192.0.2.1:5353", "[::1]:5354"}, want: []string{"192.0.2.1:5353", "[::1]:5354"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDNSServers(tc.input)
			var want []netip.AddrPort
			for _, value := range tc.want {
				want = append(want, netip.MustParseAddrPort(value))
			}
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("got=%v want=%v err=%v", got, want, err)
			}
			if len(got) > 0 {
				got[0] = netip.AddrPort{}
				again, err := parseDNSServers(tc.input)
				if err != nil || again[0] != want[0] {
					t.Fatal("result shares caller/parser storage")
				}
			}
		})
	}
	for _, value := range []string{"not-an-IP", "dns.example", "", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "127.0.0.1:0", "[::1]:65536"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			if got, err := parseDNSServers([]string{"192.0.2.1", value}); err == nil || got != nil {
				t.Fatalf("partial/invalid endpoint accepted: %v %v", got, err)
			}
		})
	}
}
