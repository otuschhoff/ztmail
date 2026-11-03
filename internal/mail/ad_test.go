package mail

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/directory"
	"github.com/otuschhoff/adbind/ad/kerberos"
	adldap "github.com/otuschhoff/adbind/ad/ldap"
)

type uniqueFixture struct {
	rows     []adclient.Entry
	err      error
	calls    int
	requests []*ldap.SearchRequest
}

func (f *uniqueFixture) FindUnique(ctx context.Context, selector directory.Selector, attributes []string) (*adclient.Entry, error) {
	f.calls++
	return directory.FindUnique(ctx, f, "DC=example,DC=test", selector, attributes)
}

func (f *uniqueFixture) Search(_ context.Context, request *ldap.SearchRequest) ([]adclient.Entry, error) {
	f.requests = append(f.requests, request)
	return f.rows, f.err
}

func TestCanonicalLookupUsesSDKUniquePrincipalSelector(t *testing.T) {
	for _, tt := range []struct {
		name string
		rows []adclient.Entry
		err  error
		want error
	}{
		{name: "success", rows: []adclient.Entry{{DN: "CN=Alice,DC=example,DC=test", Attributes: []adldap.Attribute{{Name: "mail", Values: [][]byte{[]byte("alice@example.test")}}}}}},
		{name: "not-found", want: directory.ErrNotFound},
		{name: "ambiguous", rows: []adclient.Entry{{}, {}}, want: directory.ErrAmbiguous},
		{name: "referral", err: adclient.ErrReferralRejected, want: adclient.ErrReferralRejected},
		{name: "policy", err: adclient.ErrSearchPolicy, want: adclient.ErrSearchPolicy},
		{name: "canceled", err: context.Canceled, want: context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := &uniqueFixture{rows: tt.rows, err: tt.err}
			address, err := CanonicalMail(context.Background(), fixture, kerberos.Identity{
				Principal: "alice@EXAMPLE.TEST", Realm: "EXAMPLE.TEST"})
			if (tt.want == nil && (err != nil || address.Address != "alice@example.test")) ||
				(tt.want != nil && (!errors.Is(err, tt.want) || address != (CanonicalMailbox{}))) {
				t.Fatalf("mail=%+v err=%v want=%v", address, err, tt.want)
			}
			if fixture.calls != 1 || len(fixture.requests) != 1 {
				t.Fatalf("lookup retried: calls=%d requests=%d", fixture.calls, len(fixture.requests))
			}
			request := fixture.requests[0]
			if request.Filter != "(&(objectClass=user)(|(userPrincipalName=alice@EXAMPLE.TEST)(sAMAccountName=alice)))" ||
				request.SizeLimit != 2 || !reflect.DeepEqual(request.Attributes, []string{"mail", "proxyAddresses", "objectClass"}) {
				t.Fatalf("principal lookup policy changed: %+v", request)
			}
		})
	}
}

func TestCanonicalLookupRejectsInvalidIdentityBeforeLDAP(t *testing.T) {
	for _, principal := range []string{"missing-realm", "alice@OTHER.TEST", "alice @EXAMPLE.TEST",
		"svc//host@EXAMPLE.TEST", "alice\n@EXAMPLE.TEST", "alice\\name@EXAMPLE.TEST",
		"alice\xff@EXAMPLE.TEST", strings.Repeat("a", 1025) + "@EXAMPLE.TEST"} {
		fixture := &uniqueFixture{}
		_, err := CanonicalMail(context.Background(), fixture, kerberos.Identity{Principal: principal, Realm: "EXAMPLE.TEST"})
		if err == nil || fixture.calls != 0 {
			t.Fatalf("invalid identity performed LDAP work: %q calls=%d err=%v", principal, fixture.calls, err)
		}
	}
}

func TestCanonicalHostMailboxIsOptionalOnlyForComputerObjects(t *testing.T) {
	classes := func(name string, values ...string) adldap.Attribute {
		attribute := adldap.Attribute{Name: name}
		for _, value := range values {
			attribute.Values = append(attribute.Values, []byte(value))
		}
		return attribute
	}
	for _, tt := range []struct {
		name, principal string
		attributes      []adldap.Attribute
		want            CanonicalMailbox
		err             error
	}{
		{"machine", "HOST$@EXAMPLE.TEST", []adldap.Attribute{classes("objectClass", "top", "person", "user", "computer")},
			CanonicalMailbox{HostWithoutMail: true}, nil},
		{"host-spn", "host/relay.example.test@EXAMPLE.TEST", []adldap.Attribute{classes("OBJECTCLASS", "USER", "COMPUTER")},
			CanonicalMailbox{HostWithoutMail: true}, nil},
		{"user-dollar", "USER$@EXAMPLE.TEST", []adldap.Attribute{classes("objectClass", "user")},
			CanonicalMailbox{}, directory.ErrMissingAttribute},
		{"unknown-class", "HOST$@EXAMPLE.TEST", nil, CanonicalMailbox{}, directory.ErrMissingAttribute},
		{"host-has-mail", "HOST$@EXAMPLE.TEST", []adldap.Attribute{classes("objectClass", "computer"), classes("mail", "host@example.test")},
			CanonicalMailbox{Address: "host@example.test"}, nil},
		{"host-alias-only", "HOST$@EXAMPLE.TEST", []adldap.Attribute{classes("objectClass", "computer"), classes("proxyAddresses", "smtp:alias@example.test")},
			CanonicalMailbox{HostWithoutMail: true}, nil},
		{"host-bad-mail", "HOST$@EXAMPLE.TEST", []adldap.Attribute{classes("objectClass", "computer"), classes("mail", "bad\n@example.test")},
			CanonicalMailbox{}, directory.ErrInvalidMail},
		{"host-ambiguous-mail", "HOST$@EXAMPLE.TEST", []adldap.Attribute{classes("objectClass", "computer"), classes("mail", "one@example.test", "two@example.test")},
			CanonicalMailbox{}, directory.ErrAmbiguousAttribute},
		{"host-partial-mail", "HOST$@EXAMPLE.TEST", []adldap.Attribute{classes("objectClass", "computer"), classes("proxyAddresses;range=0-*", "SMTP:one@example.test")},
			CanonicalMailbox{}, directory.ErrIncompleteAttribute},
		{"partial-class", "HOST$@EXAMPLE.TEST", []adldap.Attribute{classes("objectClass;range=0-*", "computer")},
			CanonicalMailbox{}, directory.ErrIncompleteAttribute},
		{"duplicate-class", "HOST$@EXAMPLE.TEST", []adldap.Attribute{classes("objectClass", "computer"), classes("objectClass", "computer")},
			CanonicalMailbox{}, directory.ErrAmbiguousAttribute},
		{"malformed-class", "HOST$@EXAMPLE.TEST", []adldap.Attribute{classes("objectClass", "computer", "\xff")},
			CanonicalMailbox{}, directory.ErrMalformed},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := &uniqueFixture{rows: []adclient.Entry{{DN: "CN=Account,DC=example,DC=test", Attributes: tt.attributes}}}
			result, err := CanonicalMail(t.Context(), fixture, kerberos.Identity{Principal: tt.principal, Realm: "EXAMPLE.TEST"})
			if result != tt.want || !errors.Is(err, tt.err) {
				t.Fatalf("mailbox=%+v err=%v, want=%+v err=%v", result, err, tt.want, tt.err)
			}
		})
	}
}

var _ directory.UniqueFinder = (*adclient.SearchView)(nil)

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
