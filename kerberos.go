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
	"github.com/otuschhoff/adbind/ad/observe"
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
	return adOptionsForCredentials(o, credentials)
}

func adOptionsForCredentials(o options, credentials kerberos.Options) (adclient.ADOptions, error) {
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
	settings := adclient.ADOptions{DNS: dns, Credentials: credentials, Trust: trust, Protection: "tls"}
	if o.report != nil {
		hooks := observe.Hooks{Observe: o.report.operation, Exchange: o.report.exchange}
		settings.Hooks = hooks
		settings.Credentials.Hooks = observe.Hooks{Observe: o.report.operation}
		settings.Discovery.Hooks = observe.Hooks{Observe: o.report.operation}
	}
	return settings, nil
}

func openAD(ctx context.Context, o options) (*adSession, error) {
	return chooseADCredentials(ctx, o, func(ctx context.Context, attempt options) (*adSession, error) {
		if !o.passwordPrompt {
			return openADSource(ctx, attempt)
		}
		ctx, cancel := context.WithTimeout(ctx, o.timeout)
		defer cancel()
		return openADSource(ctx, attempt)
	}, openADPassword)
}

func chooseADCredentials(ctx context.Context, o options,
	trySource func(context.Context, options) (*adSession, error),
	tryPassword func(context.Context, options) (*adSession, error)) (*adSession, error) {
	if !o.passwordPrompt {
		return trySource(ctx, o)
	}
	var sources []string
	if o.keytab != "" {
		sources = append(sources, "keytab")
	}
	sources = append(sources, "ccache")
	if runtime.GOOS == "windows" {
		sources = append(sources, "sspi")
	}
	var failures []error
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(append(failures, err)...)
		}
		attempt := o
		attempt.auth = source
		if source != "keytab" {
			attempt.keytab = ""
		}
		if source != "ccache" {
			attempt.ccache = ""
		}
		session, err := trySource(ctx, attempt)
		if err == nil {
			session.failures = append(failures, session.failures...)
			return session, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", source, err))
		if stopCredentialFallback(ctx, err) {
			return nil, errors.Join(failures...)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(append(failures, err)...)
	}
	session, err := tryPassword(ctx, o)
	if err != nil {
		return nil, errors.Join(append(failures, fmt.Errorf("password prompt: %w", err))...)
	}
	session.failures = append(failures, session.failures...)
	return session, nil
}

func stopCredentialFallback(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) ||
		errors.Is(err, kerberos.ErrClosed) || errors.Is(err, kerberos.ErrCapacity) || errors.Is(err, errADCleanup)
}

func openADSource(ctx context.Context, o options) (*adSession, error) {
	settings, err := adOptions(o)
	o.report.step("AD source configuration", err, fmt.Sprintf("source=%q principal=%q", settings.Credentials.Source, settings.Credentials.Principal))
	if err != nil {
		return nil, err
	}
	candidates := []string{settings.Credentials.Principal}
	if settings.Credentials.Source == kerberos.SourceKeytab && settings.Credentials.Principal == "" {
		entries, err := keytab.Inspect(settings.Credentials.Keytab)
		o.report.step("Keytab inspection", err, fmt.Sprintf("%d entries", len(entries)))
		if err != nil {
			return nil, fmt.Errorf("inspect keytab: %w", err)
		}
		candidates, err = principalCandidates(entries, o.realm)
		o.report.step("Keytab principal selection", err, fmt.Sprintf("candidates=%q", candidates))
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
		if stopCredentialFallback(ctx, err) {
			break
		}
	}
	return nil, errors.Join(append([]error{errors.New("no usable AD credential identity; all principal attempts failed")}, failures...)...)
}

func openADAttempt(ctx context.Context, o options, settings adclient.ADOptions) (_ *adSession, err error) {
	o.report.line("INFO", "AD identity attempt", fmt.Sprintf("source=%q principal=%q realm=%q (empty principal means auto-selection)",
		settings.Credentials.Source, settings.Credentials.Principal, settings.Credentials.Realm))
	client, err := adclient.NewAD(settings)
	o.report.step("AD client configuration", err, "SDK DNS, KDC discovery and verified LDAP TLS configured")
	if err != nil {
		return nil, err
	}
	session := &adSession{client: client}
	defer func() {
		if err != nil {
			closeErr := session.Close()
			o.report.step("Failed AD attempt cleanup", closeErr, "credential owner closed")
			if closeErr != nil {
				err = errors.Join(err, fmt.Errorf("%w: %w", errADCleanup, closeErr))
			}
		}
	}()
	session.lease, err = client.Credentials().Acquire(ctx)
	o.report.step("Acquire credential lease", err, "credentials acquired")
	if err != nil {
		return nil, fmt.Errorf("acquire AD credentials: %w", err)
	}
	session.identity, err = session.lease.Identity()
	o.report.step("Credential identity", err, fmt.Sprintf("principal=%q realm=%q krb/gssapi source=%q",
		session.identity.Principal, session.identity.Realm, session.identity.Source))
	if err != nil {
		return nil, err
	}
	_, err = session.lease.ServiceTicket(ctx, o.spn)
	o.report.step("SMTP service ticket", err, fmt.Sprintf("SPN=%q", o.spn))
	if err != nil {
		return nil, fmt.Errorf("get SMTP service ticket: %w", err)
	}
	if o.from == "" {
		session.mail, err = canonicalMail(ctx, client, session.identity)
		o.report.step("Canonical AD mail lookup", err, fmt.Sprintf("principal=%q mail=%q", session.identity.Principal, session.mail))
		if err != nil {
			return nil, fmt.Errorf("canonical AD mail for %s (or explicitly override with -f): %w", session.identity.Principal, err)
		}
	} else {
		o.report.line("SKIP", "Canonical AD mail lookup", "explicit -f override; LDAP lookup is not required by this authentication path")
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
