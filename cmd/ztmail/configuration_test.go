package main

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

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
