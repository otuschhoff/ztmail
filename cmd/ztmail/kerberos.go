package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/addns"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/adbind/ad/kerberos/keytab"
	"github.com/otuschhoff/adbind/ad/observe"
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
		settings.DNSSummary = o.report.DNSSummary
		hooks := observe.Hooks{Observe: o.report.Operation, Exchange: o.report.Exchange}
		settings.Hooks = hooks
		settings.Credentials.Hooks = observe.Hooks{Observe: o.report.Operation}
		settings.Discovery.Hooks = observe.Hooks{Observe: o.report.Operation}
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
	o.report.Step("AD source configuration", err, fmt.Sprintf("source=%q principal=%q", settings.Credentials.Source, settings.Credentials.Principal))
	if err != nil {
		return nil, err
	}
	candidates := []string{settings.Credentials.Principal}
	if settings.Credentials.Source == kerberos.SourceKeytab && settings.Credentials.Principal == "" {
		entries, err := keytab.Inspect(settings.Credentials.Keytab)
		o.report.Step("Keytab inspection", err, fmt.Sprintf("%d entries", len(entries)))
		if err != nil {
			return nil, fmt.Errorf("inspect keytab: %w", err)
		}
		candidates, err = principalCandidates(entries, o.realm)
		o.report.Step("Keytab principal selection", err, fmt.Sprintf("candidates=%q", candidates))
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
	o.report.Line("INFO", "AD identity attempt", fmt.Sprintf("source=%q principal=%q realm=%q (empty principal means auto-selection)",
		settings.Credentials.Source, settings.Credentials.Principal, settings.Credentials.Realm))
	client, err := adclient.NewAD(settings)
	o.report.Step("AD client configuration", err, "SDK DNS, KDC discovery and verified LDAP TLS configured")
	if err != nil {
		return nil, err
	}
	session := &adSession{client: client}
	defer func() {
		if err != nil {
			closeErr := session.Close()
			o.report.Step("Failed AD attempt cleanup", closeErr, "credential owner closed")
			if closeErr != nil {
				err = errors.Join(err, fmt.Errorf("%w: %w", errADCleanup, closeErr))
			}
		}
	}()
	session.lease, err = client.Credentials().Acquire(ctx)
	o.report.Step("Acquire credential lease", err, "credentials acquired")
	if err != nil {
		return nil, fmt.Errorf("acquire AD credentials: %w", err)
	}
	session.identity, err = session.lease.Identity()
	o.report.Step("Credential identity", err, fmt.Sprintf("principal=%q realm=%q krb/gssapi source=%q",
		session.identity.Principal, session.identity.Realm, session.identity.Source))
	if err != nil {
		return nil, err
	}
	_, err = session.lease.ServiceTicket(ctx, o.spn)
	o.report.Step("SMTP service ticket", err, fmt.Sprintf("SPN=%q", o.spn))
	if err != nil {
		return nil, fmt.Errorf("get SMTP service ticket: %w", err)
	}
	if o.from == "" {
		session.mail, err = canonicalMail(ctx, client, session.identity)
		o.report.Step("Canonical AD mail lookup", err, fmt.Sprintf("principal=%q mail=%q", session.identity.Principal, session.mail))
		if err != nil {
			return nil, fmt.Errorf("canonical AD mail for %s (or explicitly override with -f): %w", session.identity.Principal, err)
		}
	} else {
		o.report.Line("SKIP", "Canonical AD mail lookup", "explicit -f override; LDAP lookup is not required by this authentication path")
	}
	return session, nil
}

func (s *adSession) Close() error {
	if s.lease != nil {
		s.lease.Release()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.client.Close(ctx)
}
