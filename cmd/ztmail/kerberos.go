package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/addns"
	"github.com/otuschhoff/adbind/ad/dns"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/adbind/ad/kerberos/keytab"
	"github.com/otuschhoff/adbind/ad/observe"
	"github.com/otuschhoff/ztmail/internal/mail"
)

type adSession struct {
	client          *adclient.Client
	lease           *kerberos.Lease
	identity        kerberos.Identity
	mail            string
	hostWithoutMail bool
	failures        []error
	report          *testReport
}

var errADCleanup = errors.New("AD credential cleanup failed")
var errADCredentialsUnavailable = errors.New("AD credential acquisition unavailable")
var errADNonCredentialFailure = errors.New("AD configuration or post-acquisition failure")
var errADPasswordFailure = errors.New("password sign-in failed")

type adDNSFailure struct {
	cause   error
	failure *dns.Failure
	domain  string
	realm   string
}

func (e *adDNSFailure) Error() string {
	return fmt.Sprintf("AD DNS discovery failed for domain %q (realm %q): %s %s via %s: %v; check the DNS server or specify --dns-server with an AD-capable DNS server IP; use --verbose for the full credential and Kerberos errors",
		e.domain, e.realm, strings.TrimPrefix(e.failure.Kind.String(), "Type"), e.failure.Stage, e.failure.Server, e.failure.Cause)
}

func (e *adDNSFailure) Unwrap() error { return e.cause }

func summarizeADFailure(o options, err error) error {
	if o.verbose || errors.Is(err, errADCleanup) || errors.Is(err, context.Canceled) {
		return err
	}
	var failure *dns.Failure
	if !errors.As(err, &failure) || !failure.Server.IsValid() {
		return err
	}
	return &adDNSFailure{cause: err, failure: failure, domain: o.domain, realm: o.realm}
}

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
			return credentials, errors.New("--cred-source ccache requires --ccache or KRB5CCNAME")
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
	dns := addns.Options{Domain: o.domain, RecursionProbeZone: o.dnsProbeZone,
		QualificationPolicy: addns.QualificationOptimistic}
	if o.report != nil {
		dns.Diagnostics = addns.DiagnosticOptions{Enabled: true, Observe: o.report.DNSDiagnostic}
	}
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
		if o.debug {
			settings.Discovery.Inventory = o.report.Inventory
			settings.Hooks.Trace = o.report.Trace
		}
		hooks := observe.Hooks{Observe: o.report.Operation, Exchange: o.report.Exchange}
		hooks.Trace = settings.Hooks.Trace
		settings.Hooks = hooks
		settings.Credentials.Hooks = observe.Hooks{Observe: o.report.Operation}
		settings.Discovery.Hooks = observe.Hooks{Observe: o.report.Operation}
	}
	return settings, nil
}

func openAD(ctx context.Context, o options) (*adSession, error) {
	session, err := chooseADCredentials(ctx, o, func(ctx context.Context, attempt options) (*adSession, error) {
		if !o.passwordPrompt {
			return openADSource(ctx, attempt)
		}
		ctx, cancel := context.WithTimeout(ctx, o.timeout)
		defer cancel()
		return openADSource(ctx, attempt)
	}, openADPassword)
	return session, summarizeADFailure(o, err)
}

func chooseADCredentials(ctx context.Context, o options,
	trySource func(context.Context, options) (*adSession, error),
	tryPassword func(context.Context, options) (*adSession, error)) (*adSession, error) {
	if !o.passwordPrompt {
		return trySource(ctx, o)
	}
	issuesStart := o.report.IssueCheckpoint()
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
	issuesEnd := o.report.IssueCheckpoint()
	session, err := tryPassword(ctx, o)
	if err != nil {
		return nil, errors.Join(append(failures, fmt.Errorf("%w: %w", errADPasswordFailure, err))...)
	}
	o.report.RecoverIssues(issuesStart, issuesEnd)
	session.failures = append(failures, session.failures...)
	return session, nil
}

func reportCredentialFailures(o options, session *adSession, log io.Writer) error {
	if o.passwordPrompt && session.identity.Source == kerberos.SourcePassword && !o.verbose {
		return nil
	}
	for _, failure := range session.failures {
		if o.report != nil {
			o.report.Line("WARN", "Skipped credential identity", failure.Error())
		} else {
			if _, err := fmt.Fprintf(log, "Warning: skipped unusable AD identity: %v\n", failure); err != nil {
				return fmt.Errorf("report skipped credential identity: %w", err)
			}
		}
	}
	return nil
}

func stopCredentialFallback(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) ||
		errors.Is(err, kerberos.ErrClosed) || errors.Is(err, kerberos.ErrCapacity) || errors.Is(err, errADCleanup)
}

func openADSource(ctx context.Context, o options) (*adSession, error) {
	configDone := o.report.Measure("AD source configuration")
	settings, err := adOptions(o)
	configDone()
	o.report.Step("AD source configuration", err, fmt.Sprintf("source=%q principal=%q", settings.Credentials.Source, settings.Credentials.Principal))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errADNonCredentialFailure, err)
	}
	candidates := []string{settings.Credentials.Principal}
	if settings.Credentials.Source == kerberos.SourceKeytab && settings.Credentials.Principal == "" {
		inspectDone := o.report.Measure("Keytab inspection")
		entries, err := keytab.Inspect(settings.Credentials.Keytab)
		inspectDone()
		o.report.Step("Keytab inspection", err, fmt.Sprintf("%d entries", len(entries)))
		if err != nil {
			return nil, fmt.Errorf("inspect keytab: %w: %w", errADCredentialsUnavailable, err)
		}
		principalDone := o.report.Measure("Keytab principal selection")
		candidates, err = principalCandidates(entries, o.realm)
		principalDone()
		o.report.Step("Keytab principal selection", err, fmt.Sprintf("candidates=%q", candidates))
		if err != nil {
			return nil, fmt.Errorf("keytab principal selection: %w: %w", errADCredentialsUnavailable, err)
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
		if len(entry.Components) != 1 || entry.Components[0] == "" || strings.Contains(entry.Components[0], "/") {
			continue
		}
		principal := entry.Components[0] + "@" + strings.ToUpper(entry.Realm)
		if !seen[principal] {
			candidates = append(candidates, principal)
			seen[principal] = true
		}
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("keytab has no user or host account principals in %s (service principals ignored); check --realm or specify --principal explicitly", realm)
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
	setupDone := o.report.Measure("AD client setup")
	client, err := adclient.NewAD(settings)
	setupDone()
	o.report.Step("AD client configuration", err, "SDK DNS, KDC discovery and verified LDAP TLS configured")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errADNonCredentialFailure, err)
	}
	session := &adSession{client: client, report: o.report}
	defer func() {
		if err != nil {
			session.diagnoseDNS(ctx, err)
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
		return nil, fmt.Errorf("acquire AD credentials: %w: %w", errADCredentialsUnavailable, err)
	}
	session.identity, err = session.lease.Identity()
	o.report.Value("User", session.identity.Principal)
	reportCredentialSource(o.report, session.identity.Source, settings.Credentials)
	o.report.Step("Credential identity", err, fmt.Sprintf("principal=%q realm=%q krb/gssapi source=%q",
		session.identity.Principal, session.identity.Realm, session.identity.Source))
	if err != nil {
		return nil, fmt.Errorf("credential identity: %w: %w", errADNonCredentialFailure, err)
	}
	if !o.setDefaultFromAD {
		_, err = session.lease.ServiceTicket(ctx, o.spn)
		o.report.Step("SMTP service ticket", err, fmt.Sprintf("SPN=%q", o.spn))
		if err != nil {
			return nil, fmt.Errorf("get SMTP service ticket: %w: %w", errADNonCredentialFailure, err)
		}
	}
	if o.from == "" || o.needOwnMail {
		candidates := o.ldapRaceCandidates
		if o.noLDAPRace {
			candidates = 0
		}
		var mailbox mail.CanonicalMailbox
		mailbox, err = mail.LookupCanonicalMail(ctx, client, session.identity, candidates)
		session.mail, session.hostWithoutMail = mailbox.Address, mailbox.HostWithoutMail
		if err == nil && session.hostWithoutMail {
			o.report.Line("WARN", "Canonical AD mail lookup", "host directory account has no canonical mailbox; authenticated host credentials retained")
		} else {
			o.report.Step("Canonical AD mail lookup", err, fmt.Sprintf("principal=%q mail=%q", session.identity.Principal, session.mail))
		}
		if err != nil {
			return nil, fmt.Errorf("canonical AD mail for %s (a sender override does not supply an authenticated own-recipient address): %w: %w", session.identity.Principal, errADNonCredentialFailure, err)
		}
	} else {
		o.report.Line("SKIP", "Canonical AD mail lookup", "configured sender override; LDAP lookup is not required by this authentication path")
	}
	return session, nil
}

func (s *adSession) diagnoseDNS(ctx context.Context, lookupErr error) {
	var receipt *addns.ResolutionError
	if s.report == nil || !errors.As(lookupErr, &receipt) {
		return
	}
	dns, err := s.client.DNS()
	if err != nil {
		s.report.Step("DNS failure diagnostics", err, "")
		return
	}
	dns.Diagnose(ctx, lookupErr)
}

func reportCredentialSource(report *testReport, source kerberos.Source, credentials kerberos.Options) {
	path := ""
	switch source {
	case kerberos.SourceKeytab:
		path = credentials.Keytab
	case kerberos.SourceCCache:
		path = credentials.CCache
	}
	report.Value("Cred source", string(source))
	report.Value("Cred source path", path)
}

func (s *adSession) Close() error {
	done := s.report.Measure("AD credential cleanup")
	defer done()
	if s.lease != nil {
		s.lease.Release()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.client.Close(ctx)
}
