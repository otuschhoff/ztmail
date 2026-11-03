package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/directory"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
)

type ADBackend struct {
	Client *adclient.Client
	Lease  *kerberos.Lease
}

func CanonicalMail(ctx context.Context, client directory.UniqueFinder, identity kerberos.Identity) (string, error) {
	selector, err := directory.UserByPrincipal(identity.Principal, identity.Realm)
	if err != nil {
		return "", err
	}
	entry, err := client.FindUnique(ctx, selector, []string{"mail", "proxyAddresses"})
	if err != nil {
		return "", err
	}
	return directory.CanonicalMail(entry)
}

func LookupCanonicalMail(ctx context.Context, client *adclient.Client, identity kerberos.Identity, raceCandidates int) (address string, err error) {
	policy := adclient.SearchOptions{SingleNamingContext: true}
	if raceCandidates == 0 {
		return CanonicalMail(ctx, client.WithSearchOptions(policy), identity)
	}
	racer, err := client.WithRacing(adclient.RaceOptions{
		Mode: adclient.RaceSingleUse, MaxCandidates: raceCandidates, MaxConcurrentOperations: 1,
	})
	if err != nil {
		return "", fmt.Errorf("create LDAP racing view: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if closeErr := racer.Close(cleanup); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close LDAP racing view: %w", closeErr))
			address = ""
		}
	}()
	return CanonicalMail(ctx, racer.WithSearchOptions(policy), identity)
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

func (c *adSecurityContext) TicketMetadata() kerberos.TicketMetadata {
	return kerberos.SecurityContextTicketMetadata(c.context)
}
