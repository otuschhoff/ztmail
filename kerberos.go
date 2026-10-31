package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/addns"
	"github.com/otuschhoff/adbind/ad/directory"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/adbind/ad/kerberos/keytab"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
)

type adSession struct {
	client   *adclient.Client
	lease    *kerberos.Lease
	identity kerberos.Identity
	mail     string
	failures []error
}

var errADCleanup = errors.New("AD credential cleanup failed")

func credentialOptions(o options) (kerberos.Options, error) {
	credentials := kerberos.Options{Realm: o.realm, Principal: o.principal}
	switch {
	case o.auth != "auto":
		credentials.Source = kerberos.Source(o.auth)
	case o.keytab != "":
		credentials.Source = kerberos.SourceKeytab
	case o.ccache != "":
		credentials.Source = kerberos.SourceCCache
	case runtime.GOOS == "windows":
		credentials.Source = kerberos.SourceSSPI
	default:
		credentials.Source = kerberos.SourceCCache
	}
	var err error
	if credentials.Source == kerberos.SourceKeytab {
		credentials.Keytab, err = filepath.Abs(o.keytab)
	}
	if credentials.Source == kerberos.SourceCCache {
		path := o.ccache
		if path == "" {
			path = os.Getenv("KRB5CCNAME")
		}
		if path == "" && runtime.GOOS != "windows" {
			path = fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
		}
		if path == "" {
			return credentials, errors.New("--auth ccache requires --ccache or KRB5CCNAME")
		}
		credentials.CCache, err = cachePath(path)
	}
	if err != nil {
		return credentials, err
	}
	if credentials.Principal != "" && !strings.Contains(credentials.Principal, "@") {
		credentials.Principal += "@" + o.realm
	}
	return credentials, nil
}

func cachePath(path string) (string, error) {
	if strings.HasPrefix(path, "FILE:") {
		path = strings.TrimPrefix(path, "FILE:")
	} else if i := strings.IndexByte(path, ':'); i >= 0 && !(i == 1 && len(path) > 2 && (path[2] == '\\' || path[2] == '/')) {
		return "", errors.New("only read-only FILE credential caches are supported; specify --ccache or --keytab")
	}
	if path == "" {
		return "", errors.New("empty credential cache path")
	}
	return filepath.Abs(path)
}

func adOptions(o options) (adclient.ADOptions, error) {
	credentials, err := credentialOptions(o)
	if err != nil {
		return adclient.ADOptions{}, err
	}
	dns := addns.Options{Domain: o.domain, RecursionProbeZone: o.dnsProbeZone}
	for _, server := range o.dnsServers {
		endpoint, err := netip.ParseAddrPort(server)
		if err != nil {
			address, addressErr := netip.ParseAddr(server)
			if addressErr != nil {
				return adclient.ADOptions{}, fmt.Errorf("--dns-server must be a numeric IP or IP:port: %q", server)
			}
			endpoint = netip.AddrPortFrom(address, 53)
		}
		if !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().IsUnspecified() || endpoint.Addr().IsMulticast() {
			return adclient.ADOptions{}, fmt.Errorf("invalid --dns-server %q", server)
		}
		dns.Bootstrap = append(dns.Bootstrap, endpoint)
	}
	if len(dns.Bootstrap) != 0 {
		dns.BootstrapMethods = []addns.BootstrapMethod{addns.BootstrapExplicit}
	}
	trust, err := adclient.NewTrust(adclient.TrustPolicy{Protection: "tls", CAFile: o.ldapCA})
	if err != nil {
		return adclient.ADOptions{}, fmt.Errorf("LDAP TLS trust: %w", err)
	}
	return adclient.ADOptions{DNS: dns, Credentials: credentials, Trust: trust, Protection: "tls"}, nil
}

func openAD(ctx context.Context, o options) (*adSession, error) {
	settings, err := adOptions(o)
	if err != nil {
		return nil, err
	}
	candidates := []string{settings.Credentials.Principal}
	if settings.Credentials.Source == kerberos.SourceKeytab && settings.Credentials.Principal == "" {
		entries, err := keytab.Inspect(settings.Credentials.Keytab)
		if err != nil {
			return nil, fmt.Errorf("inspect keytab: %w", err)
		}
		candidates, err = principalCandidates(entries, o.realm)
		if err != nil {
			return nil, err
		}
	}
	return selectADSession(ctx, candidates, func(ctx context.Context, principal string) (*adSession, error) {
		attempt := settings
		attempt.Credentials.Principal = principal
		return openADAttempt(ctx, o, attempt)
	})
}

func principalCandidates(entries []keytab.EntryMetadata, realm string) ([]string, error) {
	seen := make(map[string]bool)
	var candidates []string
	for _, entry := range entries {
		if !strings.EqualFold(entry.Realm, realm) {
			continue
		}
		principal := strings.Join(entry.Components, "/") + "@" + strings.ToUpper(entry.Realm)
		if !seen[principal] {
			candidates = append(candidates, principal)
			seen[principal] = true
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("keytab has no principals in %s; specify --realm", realm)
	}
	return candidates, nil
}

func selectADSession(ctx context.Context, candidates []string, try func(context.Context, string) (*adSession, error)) (*adSession, error) {
	var failures []error
	for _, principal := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(append(failures, err)...)
		}
		session, err := try(ctx, principal)
		if err == nil {
			session.failures = failures
			return session, nil
		}
		failures = append(failures, fmt.Errorf("principal %q: %w", principal, err))
		if errors.Is(err, kerberos.ErrClosed) || errors.Is(err, kerberos.ErrCapacity) || errors.Is(err, errADCleanup) {
			break
		}
	}
	return nil, errors.Join(append([]error{errors.New("no usable AD credential identity; all principal attempts failed")}, failures...)...)
}

func openADAttempt(ctx context.Context, o options, settings adclient.ADOptions) (_ *adSession, err error) {
	client, err := adclient.NewAD(settings)
	if err != nil {
		return nil, err
	}
	session := &adSession{client: client}
	defer func() {
		if err != nil {
			if closeErr := session.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("%w: %w", errADCleanup, closeErr))
			}
		}
	}()
	session.lease, err = client.Credentials().Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire AD credentials: %w", err)
	}
	session.identity, err = session.lease.Identity()
	if err != nil {
		return nil, err
	}
	if _, err := session.lease.ServiceTicket(ctx, o.spn); err != nil {
		return nil, fmt.Errorf("get SMTP service ticket: %w", err)
	}
	if o.from == "" {
		session.mail, err = canonicalMail(ctx, client, session.identity)
		if err != nil {
			return nil, fmt.Errorf("canonical AD mail for %s (or explicitly override with -f): %w", session.identity.Principal, err)
		}
	}
	return session, nil
}

type adSearcher interface {
	Search(context.Context, *ldap.SearchRequest) ([]adclient.Entry, error)
}

func canonicalMail(ctx context.Context, client adSearcher, identity kerberos.Identity) (string, error) {
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
	filter, err := identityFilter(identity)
	if err != nil {
		return "", err
	}
	request := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		filter, []string{"mail", "proxyAddresses"}, nil)
	entries, err := client.Search(ctx, request)
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

func identityFilter(identity kerberos.Identity) (string, error) {
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

func (s *adSession) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	dns, err := s.client.DNS()
	if err != nil {
		return nil, err
	}
	result, err := dns.LookupHost(ctx, host)
	return result.Addresses, err
}

func (s *adSession) NewSecurityContext(ctx context.Context, spn string, state *tls.ConnectionState) (securityContext, error) {
	security, err := s.lease.NewSecurityContextWithTLS(ctx, spn, state)
	if err != nil {
		return nil, err
	}
	return &adSecurityContext{context: security, target: spn}, nil
}

func (s *adSession) Close() error {
	if s.lease != nil {
		s.lease.Release()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.client.Close(ctx)
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
