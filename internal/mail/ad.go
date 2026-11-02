package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/directory"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
)

type ADBackend struct {
	Client *adclient.Client
	Lease  *kerberos.Lease
}
type ADSearcher interface {
	Search(context.Context, *ldap.SearchRequest) ([]adclient.Entry, error)
	SearchWithOptions(context.Context, *ldap.SearchRequest, adclient.SearchOptions) ([]adclient.Entry, error)
}

func CanonicalMail(ctx context.Context, client ADSearcher, identity kerberos.Identity) (string, error) {
	root, err := directory.RootDSE(ctx, client)
	if err != nil {
		return "", err
	}
	base, err := directory.SingleValue(root, "defaultNamingContext")
	if err != nil {
		return "", err
	}
	if _, err := ldap.ParseDN(base); err != nil {
		return "", fmt.Errorf("invalid AD naming context: %w", err)
	}
	filter, err := IdentityFilter(identity)
	if err != nil {
		return "", err
	}
	request := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		filter, []string{"mail", "proxyAddresses"}, nil)
	entries, err := client.SearchWithOptions(ctx, request, adclient.SearchOptions{SingleNamingContext: true})
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", directory.ErrNotFound
	}
	if len(entries) != 1 {
		return "", directory.ErrAmbiguous
	}
	return directory.CanonicalMail(&entries[0])
}

func IdentityFilter(identity kerberos.Identity) (string, error) {
	name, realm, found := strings.Cut(identity.Principal, "@")
	if !found || name == "" || realm == "" || strings.Contains(realm, "@") || !strings.EqualFold(realm, identity.Realm) || strings.ContainsAny(identity.Principal, "\r\n\x00") {
		return "", errors.New("invalid authenticated AD identity")
	}
	alternatives := "(userPrincipalName=" + ldap.EscapeFilter(identity.Principal) + ")"
	if strings.Contains(name, "/") {
		alternatives += "(servicePrincipalName=" + ldap.EscapeFilter(name) + ")"
	} else {
		alternatives += "(sAMAccountName=" + ldap.EscapeFilter(name) + ")"
	}
	return "(&(objectClass=user)(|" + alternatives + "))", nil
}

func (s *ADBackend) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	dns, err := s.Client.DNS()
	if err != nil {
		return nil, err
	}
	result, err := dns.LookupHost(ctx, host)
	return result.Addresses, err
}

func (s *ADBackend) NewSecurityContext(ctx context.Context, spn string, state *tls.ConnectionState) (SecurityContext, error) {
	security, err := s.Lease.NewSecurityContextWithTLS(ctx, spn, state)
	if err != nil {
		return nil, err
	}
	return &adSecurityContext{context: security, target: spn}, nil
}

type adSecurityContext struct {
	context kerberos.SecurityContext
	target  string
}

func (c *adSecurityContext) Start() ([]byte, error) {
	token, more, err := c.context.InitSecContextWithOptions(c.target, nil, []int{flags.APOptionMutualRequired})
	if err == nil && !more {
		return nil, errors.New("AD context completed before mutual authentication")
	}
	return token, err
}

func (c *adSecurityContext) Step(input []byte) ([]byte, bool, error) {
	token, more, err := c.context.InitSecContext(c.target, input)
	return token, !more, err
}

func (c *adSecurityContext) Negotiate(input []byte) ([]byte, error) {
	return c.context.NegotiateSaslAuth(input, "")
}

func (c *adSecurityContext) Close() error { return c.context.DeleteSecContext() }
