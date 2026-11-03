package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/directory"
	"github.com/otuschhoff/adbind/ad/kerberos"
	adldap "github.com/otuschhoff/adbind/ad/ldap"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
)

type ADBackend struct {
	Client *adclient.Client
	Lease  *kerberos.Lease
}

type ADResolver struct {
	Client *adclient.Client
}

func (s ADResolver) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return (&ADBackend{Client: s.Client}).Resolve(ctx, host)
}

type CanonicalMailbox struct {
	Address         string
	HostWithoutMail bool
}

func CanonicalMail(ctx context.Context, client directory.UniqueFinder, identity kerberos.Identity) (CanonicalMailbox, error) {
	selector, err := directory.UserByPrincipal(identity.Principal, identity.Realm)
	if err != nil {
		return CanonicalMailbox{}, err
	}
	entry, err := client.FindUnique(ctx, selector, []string{"mail", "proxyAddresses", "objectClass"})
	if err != nil {
		return CanonicalMailbox{}, err
	}
	address, mailErr := directory.CanonicalMail(entry)
	if !errors.Is(mailErr, directory.ErrMissingAttribute) {
		return CanonicalMailbox{Address: address}, mailErr
	}
	host, err := directoryComputer(entry)
	if err != nil {
		return CanonicalMailbox{}, fmt.Errorf("host objectClass metadata: %w", err)
	}
	if host {
		return CanonicalMailbox{HostWithoutMail: true}, nil
	}
	return CanonicalMailbox{}, mailErr
}

func directoryComputer(entry *adldap.Entry) (bool, error) {
	host, found := false, false
	for _, attribute := range entry.Attributes {
		name, _, optioned := strings.Cut(attribute.Name, ";")
		if !strings.EqualFold(name, "objectClass") {
			continue
		}
		if optioned {
			return false, directory.ErrIncompleteAttribute
		}
		if found {
			return false, directory.ErrAmbiguousAttribute
		}
		found = true
		for _, value := range attribute.Values {
			if len(value) == 0 || !utf8.Valid(value) || strings.ContainsAny(string(value), "\x00\r\n") {
				return false, directory.ErrMalformed
			}
			host = host || strings.EqualFold(string(value), "computer")
		}
	}
	return host, nil
}

func LookupCanonicalMail(ctx context.Context, client *adclient.Client, identity kerberos.Identity, raceCandidates int) (mailbox CanonicalMailbox, err error) {
	policy := adclient.SearchOptions{SingleNamingContext: true}
	if raceCandidates == 0 {
		return CanonicalMail(ctx, client.WithSearchOptions(policy), identity)
	}
	racer, err := client.WithRacing(adclient.RaceOptions{
		Mode: adclient.RaceSingleUse, MaxCandidates: raceCandidates, MaxConcurrentOperations: 1,
	})
	if err != nil {
		return CanonicalMailbox{}, fmt.Errorf("create LDAP racing view: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if closeErr := racer.Close(cleanup); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close LDAP racing view: %w", closeErr))
			mailbox = CanonicalMailbox{}
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
