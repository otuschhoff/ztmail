package mail

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/directory"
	"github.com/otuschhoff/adbind/ad/kerberos"
	adldap "github.com/otuschhoff/adbind/ad/ldap"
)

func TestCanonicalQuotedMailboxPolicy(t *testing.T) {
	attribute := func(name string, values ...string) adldap.Attribute {
		a := adldap.Attribute{Name: name}
		for _, value := range values {
			a.Values = append(a.Values, []byte(value))
		}
		return a
	}
	for _, tc := range []struct {
		name       string
		attributes []adldap.Attribute
		want       string
		err        error
	}{
		{"quoted mail", []adldap.Attribute{attribute("mail", `"a b"@example.test`)}, `"a b"@example.test`, nil},
		{"quoted primary", []adldap.Attribute{attribute("proxyAddresses", `SMTP:"a\"b"@example.test`, "smtp:alias@example.test"), attribute("mail", "fallback@example.test")}, `"a\"b"@example.test`, nil},
		{"quoted alias", []adldap.Attribute{attribute("proxyAddresses", `smtp:"a b"@example.test`), attribute("mail", "fallback@example.test")}, "fallback@example.test", nil},
		{"quoted fallback validated", []adldap.Attribute{attribute("proxyAddresses", "SMTP:primary@example.test"), attribute("mail", `"a b"@example.test`)}, "primary@example.test", nil},
		{"unnecessary quotes", []adldap.Attribute{attribute("mail", `"alice"@example.test`)}, "alice@example.test", nil},
		{"quoted at", []adldap.Attribute{attribute("mail", `"a@b"@example.test`)}, `"a@b"@example.test`, nil},
		{"quoted local and unrelated proxy", []adldap.Attribute{attribute("proxyAddresses", "X500:/o=Company", `SMTP:"a\\b"@example.test`)}, `"a\\b"@example.test`, nil},
		{"alias not substituted", []adldap.Attribute{attribute("proxyAddresses", `smtp:"a b"@example.test`)}, "", directory.ErrMissingAttribute},
		{"duplicate primary", []adldap.Attribute{attribute("proxyAddresses", `SMTP:"a b"@example.test`, `SMTP:"a b"@example.test`)}, "", directory.ErrAmbiguousAttribute},
		{"duplicate mail", []adldap.Attribute{attribute("mail", `"a b"@example.test`, "other@example.test")}, "", directory.ErrAmbiguousAttribute},
		{"duplicate proxy attributes", []adldap.Attribute{attribute("proxyAddresses", `SMTP:"a b"@example.test`), attribute("PROXYADDRESSES", "smtp:alias@example.test")}, "", directory.ErrAmbiguousAttribute},
		{"partial proxy", []adldap.Attribute{attribute("proxyAddresses;range=0-*", `SMTP:"a b"@example.test`)}, "", directory.ErrIncompleteAttribute},
		{"partial fallback", []adldap.Attribute{attribute("proxyAddresses", `SMTP:"a b"@example.test`), attribute("mail;binary", "fallback@example.test")}, "", directory.ErrIncompleteAttribute},
		{"malformed alias", []adldap.Attribute{attribute("proxyAddresses", `SMTP:"a b"@example.test`, "smtp:invalid")}, "", directory.ErrInvalidMail},
		{"mixed prefix", []adldap.Attribute{attribute("proxyAddresses", `Smtp:"a b"@example.test`)}, "", directory.ErrInvalidMail},
		{"invalid fallback", []adldap.Attribute{attribute("proxyAddresses", `SMTP:"a b"@example.test`), attribute("mail", "invalid")}, "", directory.ErrInvalidMail},
		{"nonbare fallback", []adldap.Attribute{attribute("proxyAddresses", `SMTP:"a b"@example.test`), attribute("mail", "<fallback@example.test>")}, "", directory.ErrInvalidMail},
		{"empty proxy", []adldap.Attribute{attribute("proxyAddresses", `SMTP:"a b"@example.test`, "")}, "", directory.ErrInvalidMail},
		{"invalid unrelated proxy", []adldap.Attribute{attribute("proxyAddresses", `SMTP:"a b"@example.test`, "X500:/o=Bad\nproxy")}, "", directory.ErrInvalidMail},
		{"trailing comment", []adldap.Attribute{attribute("mail", `"a b"@example.test (comment)`)}, "", directory.ErrInvalidMail},
		{"overlong", []adldap.Attribute{attribute("mail", `"`+string(bytes.Repeat([]byte("a"), 250))+` b"@example.test`)}, "", directory.ErrInvalidMail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := adclient.Entry{DN: "CN=Alice,DC=example,DC=test", Attributes: tc.attributes}
			original := make([]adldap.Attribute, len(tc.attributes))
			for i, a := range tc.attributes {
				original[i] = adldap.Attribute{Name: a.Name}
				for _, value := range a.Values {
					original[i].Values = append(original[i].Values, bytes.Clone(value))
				}
			}
			fixture := &uniqueFixture{rows: []adclient.Entry{entry}}
			result, err := CanonicalMail(t.Context(), fixture, kerberos.Identity{Principal: "alice@EXAMPLE.TEST", Realm: "EXAMPLE.TEST"})
			if result.Address != tc.want || result.HostWithoutMail || !errors.Is(err, tc.err) {
				t.Fatalf("mailbox=%+v err=%v; want %q, %v", result, err, tc.want, tc.err)
			}
			if fixture.calls != 1 || !reflect.DeepEqual(entry.Attributes, original) {
				t.Fatal("lookup retried or caller-owned entry mutated")
			}
		})
	}
}
