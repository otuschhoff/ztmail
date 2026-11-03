package mail

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/directory"
	"github.com/otuschhoff/adbind/ad/kerberos"
	adldap "github.com/otuschhoff/adbind/ad/ldap"
)

type directoryFixture struct {
	root      func(*ldap.SearchRequest) ([]adclient.Entry, error)
	user      func(*ldap.SearchRequest, adclient.SearchOptions) ([]adclient.Entry, error)
	rootCalls int
	userCalls int
}

func (f *directoryFixture) Search(_ context.Context, request *ldap.SearchRequest) ([]adclient.Entry, error) {
	f.rootCalls++
	return f.root(request)
}

func (f *directoryFixture) SearchWithOptions(_ context.Context, request *ldap.SearchRequest, options adclient.SearchOptions) ([]adclient.Entry, error) {
	f.userCalls++
	return f.user(request, options)
}

func rootEntry(base string) []adclient.Entry {
	return []adclient.Entry{{Attributes: []adldap.Attribute{{Name: "defaultNamingContext", Values: [][]byte{[]byte(base)}}}}}
}

func TestCanonicalLookupScopesOnlyUserSearch(t *testing.T) {
	for _, tt := range []struct {
		name string
		rows []adclient.Entry
		err  error
		want error
	}{
		{name: "success", rows: []adclient.Entry{{Attributes: []adldap.Attribute{{Name: "mail", Values: [][]byte{[]byte("alice@example.test")}}}}}},
		{name: "not-found", want: directory.ErrNotFound},
		{name: "ambiguous", rows: []adclient.Entry{{}, {}}, want: directory.ErrAmbiguous},
		{name: "referral", err: adclient.ErrReferralRejected, want: adclient.ErrReferralRejected},
		{name: "policy", err: adclient.ErrSearchPolicy, want: adclient.ErrSearchPolicy},
		{name: "canceled", err: context.Canceled, want: context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := &directoryFixture{
				root: func(r *ldap.SearchRequest) ([]adclient.Entry, error) {
					if r.BaseDN != "" || r.Scope != ldap.ScopeBaseObject || len(r.Controls) != 0 {
						t.Fatalf("RootDSE must stay unscoped: %+v", r)
					}
					return rootEntry("DC=example,DC=test"), nil
				},
				user: func(r *ldap.SearchRequest, o adclient.SearchOptions) ([]adclient.Entry, error) {
					if o != (adclient.SearchOptions{SingleNamingContext: true}) || r.BaseDN != "DC=example,DC=test" ||
						r.Scope != ldap.ScopeWholeSubtree || r.SizeLimit != 2 || len(r.Controls) != 0 ||
						!reflect.DeepEqual(r.Attributes, []string{"mail", "proxyAddresses"}) {
						t.Fatalf("user lookup must use verified base and SDK-managed policy/paging: %+v %+v", r, o)
					}
					return tt.rows, tt.err
				},
			}
			address, err := CanonicalMail(context.Background(), fixture, kerberos.Identity{
				Principal: "alice@EXAMPLE.TEST", Realm: "EXAMPLE.TEST"})
			if (tt.want == nil && (err != nil || address != "alice@example.test")) ||
				(tt.want != nil && (!errors.Is(err, tt.want) || address != "")) {
				t.Fatalf("mail=%q err=%v want=%v", address, err, tt.want)
			}
			if fixture.rootCalls != 1 || fixture.userCalls != 1 {
				t.Fatalf("lookup retried or bypassed scope: root=%d user=%d", fixture.rootCalls, fixture.userCalls)
			}
		})
	}
}

func TestCanonicalLookupRejectsInvalidMetadataBeforeUserSearch(t *testing.T) {
	for _, tt := range []struct {
		name string
		rows []adclient.Entry
		err  error
	}{
		{name: "root-failure", err: errors.New("RootDSE unavailable")},
		{name: "missing-context", rows: []adclient.Entry{{}}},
		{name: "invalid-context", rows: rootEntry("not a DN")},
		{name: "ambiguous-root", rows: []adclient.Entry{{}, {}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := &directoryFixture{
				root: func(*ldap.SearchRequest) ([]adclient.Entry, error) { return tt.rows, tt.err },
				user: func(*ldap.SearchRequest, adclient.SearchOptions) ([]adclient.Entry, error) {
					t.Fatal("invalid metadata must not trigger a user lookup")
					return nil, nil
				},
			}
			_, err := CanonicalMail(context.Background(), fixture, kerberos.Identity{Principal: "alice@EXAMPLE.TEST", Realm: "EXAMPLE.TEST"})
			if err == nil || (tt.err != nil && !errors.Is(err, tt.err)) || fixture.rootCalls != 1 || fixture.userCalls != 0 {
				t.Fatalf("root=%d user=%d err=%v", fixture.rootCalls, fixture.userCalls, err)
			}
		})
	}
}

var _ ADSearcher = (*adclient.Client)(nil)

type fakeADContext struct {
	kerberos.SecurityContext
	target   string
	options  []int
	more     bool
	fail     error
	offer    []byte
	authzid  string
	closed   bool
	metadata kerberos.TicketMetadata
}

func (f *fakeADContext) InitSecContextWithOptions(target string, input []byte, options []int) ([]byte, bool, error) {
	f.target, f.options = target, options
	return []byte("request"), f.more, f.fail
}
func (f *fakeADContext) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	f.target = target
	return []byte("reply"), f.more, f.fail
}
func (f *fakeADContext) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	f.offer, f.authzid = input, authzid
	return []byte("selection"), f.fail
}
func (f *fakeADContext) DeleteSecContext() error { f.closed = true; return f.fail }

func (f *fakeADContext) TicketMetadata() kerberos.TicketMetadata { return f.metadata }

func TestADSecurityContextDelegatesToSDK(t *testing.T) {
	fake := &fakeADContext{more: true, metadata: testTicketMetadata(time.Now())}
	c := &adSecurityContext{context: fake, target: "smtp/mailgw.example.com"}
	token, err := c.Start()
	if err != nil || string(token) != "request" || fake.target != c.target || !reflect.DeepEqual(fake.options, []int{2}) {
		t.Fatalf("Start=%q %v target=%s options=%v", token, err, fake.target, fake.options)
	}
	fake.more = false
	if _, done, err := c.Step([]byte("AP-REP")); err != nil || !done {
		t.Fatalf("Step=%v %v", done, err)
	}
	selection, err := c.Negotiate([]byte("offer"))
	if err != nil || string(selection) != "selection" || string(fake.offer) != "offer" || fake.authzid != "" {
		t.Fatalf("Negotiate=%q %v", selection, err)
	}
	if err := c.Close(); err != nil || !fake.closed {
		t.Fatalf("Close=%v closed=%v", err, fake.closed)
	}
	if got := c.TicketMetadata(); got != fake.metadata {
		t.Fatal("metadata did not delegate to the actual SDK context or survive deletion")
	}
	if _, err := c.Start(); err == nil {
		t.Fatal("premature context completion accepted")
	}
}
