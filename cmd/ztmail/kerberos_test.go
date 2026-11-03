package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/addns"
	"github.com/otuschhoff/adbind/ad/directory"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/adbind/ad/kerberos/keytab"
	adldap "github.com/otuschhoff/adbind/ad/ldap"
)

func TestPrincipalCandidates(t *testing.T) {
	entries := []keytab.EntryMetadata{
		{Realm: "EXAMPLE.COM", Components: []string{"first"}},
		{Realm: "EXAMPLE.COM", Components: []string{"first"}},
		{Realm: "example.com", Components: []string{"smtp", "relay.example.com"}},
		{Realm: "EXAMPLE.COM", Components: []string{"HOST$"}},
		{Realm: "EXAMPLE.COM", Components: []string{"host", "relay.example.com"}},
		{Realm: "EXAMPLE.COM", Components: []string{"ldap", "relay.example.com"}},
		{Realm: "EXAMPLE.COM", Components: []string{"second"}},
		{Realm: "OTHER.COM", Components: []string{"foreign"}},
	}
	got, err := principalCandidates(entries, "EXAMPLE.COM")
	want := []string{"first@EXAMPLE.COM", "HOST$@EXAMPLE.COM", "second@EXAMPLE.COM"}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates=%v err=%v; want %v", got, err, want)
	}
	if _, err := principalCandidates(entries, "ABSENT.COM"); err == nil {
		t.Fatal("empty realm selection accepted")
	}
}

func TestPrincipalCandidatesRejectSPNOnlyKeytabs(t *testing.T) {
	for _, entries := range [][]keytab.EntryMetadata{
		{{Realm: "EXAMPLE.COM", Components: []string{"smtp", "relay.example.com"}}},
		{{Realm: "EXAMPLE.COM", Components: []string{"host", "relay.example.com"}}},
		{{Realm: "EXAMPLE.COM", Components: []string{"ldap/relay.example.com"}}},
		{{Realm: "EXAMPLE.COM", Components: []string{""}}},
		{{Realm: "EXAMPLE.COM"}},
	} {
		got, err := principalCandidates(entries, "EXAMPLE.COM")
		if len(got) != 0 || err == nil || !strings.Contains(err.Error(), "service principals ignored") {
			t.Fatalf("unsuitable principals accepted or not explained: %v %v", got, err)
		}
	}
}

func TestExplicitServicePrincipalIsPreserved(t *testing.T) {
	credentials, err := credentialOptions(options{auth: "keytab", keytab: "mailer.keytab",
		principal: "smtp/relay.example.com", realm: "EXAMPLE.COM"})
	if err != nil || credentials.Principal != "smtp/relay.example.com@EXAMPLE.COM" {
		t.Fatalf("explicit principal=%q err=%v", credentials.Principal, err)
	}
}

func TestSelectADSessionTriesPrincipals(t *testing.T) {
	var attempts []string
	selected := &adSession{mail: "canonical@example.com"}
	got, err := selectADSession(context.Background(), []string{"bad", "no-mail", "good", "unused"},
		func(_ context.Context, principal string) (*adSession, error) {
			attempts = append(attempts, principal)
			if principal != "good" {
				return nil, errors.New("not usable")
			}
			return selected, nil
		})
	if err != nil || got != selected || !reflect.DeepEqual(attempts, []string{"bad", "no-mail", "good"}) {
		t.Fatalf("got=%v attempts=%v err=%v", got, attempts, err)
	}
}

func TestSelectADSessionFailures(t *testing.T) {
	for _, stop := range []error{errors.New("authentication failed"), kerberos.ErrCapacity, errADCleanup} {
		calls := 0
		_, err := selectADSession(context.Background(), []string{"one", "two"}, func(context.Context, string) (*adSession, error) {
			calls++
			return nil, stop
		})
		wantCalls := 2
		if errors.Is(stop, kerberos.ErrCapacity) || errors.Is(stop, errADCleanup) {
			wantCalls = 1
		}
		if calls != wantCalls || !errors.Is(err, stop) || !strings.Contains(err.Error(), "one") {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := selectADSession(ctx, []string{"one"}, func(context.Context, string) (*adSession, error) {
		t.Fatal("attempt made after cancellation")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestCredentialOptions(t *testing.T) {
	t.Setenv("KRB5_CONFIG", "/missing/krb5.conf")
	t.Setenv("KRB5CCNAME", "FILE:"+filepath.Join(t.TempDir(), "cache"))
	for _, tt := range []struct {
		o      options
		source kerberos.Source
	}{
		{options{auth: "auto", keytab: "mailer.keytab", principal: "mailer", realm: "EXAMPLE.COM"}, kerberos.SourceKeytab},
		{options{auth: "auto", ccache: "cache", realm: "EXAMPLE.COM"}, kerberos.SourceCCache},
		{options{auth: "ccache", realm: "EXAMPLE.COM"}, kerberos.SourceCCache},
		{options{auth: "sspi", realm: "EXAMPLE.COM"}, kerberos.SourceSSPI},
	} {
		got, err := credentialOptions(tt.o)
		if err != nil || got.Source != tt.source {
			t.Fatalf("options=%+v err=%v", got, err)
		}
		if tt.o.principal != "" && got.Principal != "mailer@EXAMPLE.COM" {
			t.Fatalf("principal=%s", got.Principal)
		}
		if got.Keytab != "" && !filepath.IsAbs(got.Keytab) {
			t.Fatal("relative keytab passed to SDK")
		}
		if got.CCache != "" && !filepath.IsAbs(got.CCache) {
			t.Fatal("relative cache passed to SDK")
		}
	}
}

func TestCachePath(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "cache")
	for _, input := range []string{absolute, "FILE:" + absolute} {
		got, err := cachePath(input)
		if err != nil || got != absolute {
			t.Fatalf("%q: %q %v", input, got, err)
		}
	}
	for _, input := range []string{"DIR:/tmp/cache", "KCM:", "KEYRING:persistent:1000", "FILE:", ""} {
		if _, err := cachePath(input); err == nil {
			t.Fatalf("unsupported cache %q accepted", input)
		}
	}
}

func TestExternalCacheIsReadOnlyAndIgnoresKrbConfig(t *testing.T) {
	t.Setenv("KRB5_CONFIG", filepath.Join(t.TempDir(), "missing.conf"))
	path := filepath.Join(t.TempDir(), "external.ccache")
	content := []byte("not a valid credential cache")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	o := options{auth: "ccache", ccache: path, domain: "corp.example", realm: "CORP.EXAMPLE",
		dnsProbeZone: "example.com", spn: "smtp/mailgw.corp.example", from: "override@example.com"}
	session, err := openAD(context.Background(), o)
	if session != nil || err == nil || !strings.Contains(err.Error(), "invalid external ccache") {
		t.Fatalf("expected cache parse error, not config/network work: session=%v err=%v", session, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(content) {
		t.Fatalf("external cache was modified: after=%q err=%v", after, err)
	}
}

func TestADOptions(t *testing.T) {
	o := options{auth: "keytab", keytab: "mailer.keytab", domain: "corp.example", realm: "CORP.EXAMPLE", dnsProbeZone: "example.com"}
	settings, err := adOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	if settings.DNS.Bootstrap != nil || settings.DNS.BootstrapMethods != nil {
		t.Fatal("default must delegate OS DNS bootstrap to adclient")
	}
	if settings.DNS.QualificationPolicy != addns.QualificationOptimistic || settings.DNS.Diagnostics.Enabled {
		t.Fatal("CLI must use optimistic qualification without normal-send diagnostics")
	}
	if settings.Credentials.KDCProvider != nil || settings.Credentials.DialContext != nil {
		t.Fatal("application must not override composed KDC routing")
	}
	client, err := adclient.NewAD(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	o.dnsServers = []string{"192.0.2.1", "[2001:db8::1]:5353"}
	settings, err = adOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:53"), netip.MustParseAddrPort("[2001:db8::1]:5353")}
	if !reflect.DeepEqual(settings.DNS.Bootstrap, want) || !reflect.DeepEqual(settings.DNS.BootstrapMethods, []addns.BootstrapMethod{addns.BootstrapExplicit}) {
		t.Fatalf("bootstrap=%v methods=%v", settings.DNS.Bootstrap, settings.DNS.BootstrapMethods)
	}
	for _, server := range []string{"resolver.example.com", "0.0.0.0", "192.0.2.1:0", "224.0.0.1"} {
		o.dnsServers = []string{server}
		if _, err := adOptions(o); err == nil {
			t.Fatalf("invalid DNS server %q accepted", server)
		}
	}
}

func TestOptimisticDNSNeedsNoProbeZoneForSubmission(t *testing.T) {
	for _, relay := range []string{"mailgw.corp.example", "relay.external.example"} {
		t.Run(relay, func(t *testing.T) {
			settings, err := adOptions(options{auth: "keytab", keytab: "mailer.keytab",
				domain: "corp.example", realm: "CORP.EXAMPLE", relay: relay})
			if err != nil {
				t.Fatal(err)
			}
			if settings.DNS.QualificationPolicy != addns.QualificationOptimistic ||
				settings.DNS.RecursionProbeZone != "" || settings.DNS.Diagnostics.Enabled {
				t.Fatal("optimistic submission must not require recursion diagnostics or a probe zone")
			}
			client, err := adclient.NewAD(settings)
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type fakeDirectory struct {
	t        *testing.T
	requests []*ldap.SearchRequest
	entries  []adclient.Entry
	err      error
}

func attribute(name string, values ...string) adldap.Attribute {
	a := adldap.Attribute{Name: name}
	for _, value := range values {
		a.Values = append(a.Values, []byte(value))
	}
	return a
}

func (f *fakeDirectory) Search(ctx context.Context, request *ldap.SearchRequest) ([]adclient.Entry, error) {
	if request.BaseDN != "" {
		return f.SearchWithOptions(ctx, request, adclient.SearchOptions{SingleNamingContext: true})
	}
	f.requests = append(f.requests, request)
	if request.BaseDN != "" || request.Scope != ldap.ScopeBaseObject || len(request.Controls) != 0 {
		f.t.Fatal("only unscoped RootDSE may use Search")
	}
	return []adclient.Entry{{Attributes: []adldap.Attribute{attribute("defaultNamingContext", "DC=corp,DC=example")}}}, nil
}

func (f *fakeDirectory) SearchWithOptions(_ context.Context, request *ldap.SearchRequest, options adclient.SearchOptions) ([]adclient.Entry, error) {
	f.requests = append(f.requests, request)
	if !options.SingleNamingContext {
		f.t.Fatal("canonical-user lookup must stay in the selected naming context")
	}
	if request.BaseDN != "DC=corp,DC=example" || request.SizeLimit != 2 || request.Scope != ldap.ScopeWholeSubtree {
		f.t.Fatalf("unbounded or guessed LDAP search: %+v", request)
	}
	return f.entries, f.err
}

func (f *fakeDirectory) FindUnique(ctx context.Context, selector directory.Selector, attributes []string) (*adclient.Entry, error) {
	root, err := directory.RootDSE(ctx, f)
	if err != nil {
		return nil, err
	}
	base, err := directory.SingleValue(root, "defaultNamingContext")
	if err != nil {
		return nil, err
	}
	return directory.FindUnique(ctx, f, base, selector, attributes)
}

func TestCanonicalMailUsesAuthenticatedIdentity(t *testing.T) {
	identity := kerberos.Identity{Principal: "mailer@CORP.EXAMPLE", Realm: "CORP.EXAMPLE"}
	for _, tt := range []struct {
		name    string
		entries []adclient.Entry
		err     error
		want    string
		fail    bool
	}{
		{"primary", []adclient.Entry{{Attributes: []adldap.Attribute{attribute("mail", "fallback@example.com"), attribute("proxyAddresses", "smtp:alias@example.com", "SMTP:primary@example.com")}}}, nil, "primary@example.com", false},
		{"mail", []adclient.Entry{{Attributes: []adldap.Attribute{attribute("mail", "mailer@example.com")}}}, nil, "mailer@example.com", false},
		{"absent", nil, nil, "", true},
		{"ambiguous", []adclient.Entry{{}, {}}, nil, "", true},
		{"no-mail", []adclient.Entry{{}}, nil, "", true},
		{"bad-mail", []adclient.Entry{{Attributes: []adldap.Attribute{attribute("mail", "bad\n@example.com")}}}, nil, "", true},
		{"failed-search", nil, errors.New("LDAP failed"), "", true},
		{"referral-rejected", nil, adclient.ErrReferralRejected, "", true},
		{"unsupported-control", nil, ldap.NewError(ldap.LDAPResultUnavailableCriticalExtension, errors.New("critical control unsupported")), "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for i := range tt.entries {
				tt.entries[i].DN = "CN=Mailer,DC=corp,DC=example"
			}
			client := &fakeDirectory{t: t, entries: tt.entries, err: tt.err}
			got, err := canonicalMail(context.Background(), client, identity)
			if got.Address != tt.want || (err != nil) != tt.fail {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			if len(client.requests) != 2 || !strings.Contains(client.requests[1].Filter, "sAMAccountName=mailer") {
				t.Fatalf("identity lookup requests=%v", client.requests)
			}
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Fatalf("search error lost: %v", err)
			}
		})
	}
}

func TestIdentityFilter(t *testing.T) {
	for _, tt := range []struct{ principal, want string }{
		{"mailer@EXAMPLE.COM", "(sAMAccountName=mailer)"},
		{"smtp/mailgw.example.com@EXAMPLE.COM", "(servicePrincipalName=smtp/mailgw.example.com)"},
		{"user*)(x@EXAMPLE.COM", `(sAMAccountName=user\2a\29\28x)`},
	} {
		fixture := &fakeDirectory{t: t}
		_, err := canonicalMail(context.Background(), fixture, kerberos.Identity{Principal: tt.principal, Realm: "EXAMPLE.COM"})
		if !errors.Is(err, directory.ErrNotFound) || len(fixture.requests) != 2 ||
			!strings.Contains(fixture.requests[1].Filter, tt.want) {
			t.Fatalf("requests=%v err=%v", fixture.requests, err)
		}
	}
	if _, err := canonicalMail(context.Background(), &fakeDirectory{t: t}, kerberos.Identity{Principal: "missing-realm", Realm: "EXAMPLE.COM"}); err == nil {
		t.Fatal("invalid identity accepted")
	}
}

var _ directory.Searcher = (*fakeDirectory)(nil)
