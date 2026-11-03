package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/otuschhoff/ztmail/internal/mail"
	"github.com/spf13/cobra"
)

type options struct {
	domain, realm, relay, hello, spn                      string
	auth, keytab, principal, ccache                       string
	dnsProbeZone, ldapCA                                  string
	dnsServers                                            []string
	from, fullName, tlsMode                               string
	port                                                  int
	timeout                                               time.Duration
	readHeaders, ignoreDots, verbose                      bool
	passwordPrompt                                        bool
	testMode                                              bool
	testMail                                              bool
	debug                                                 bool
	needOwnMail                                           bool
	report                                                *testReport
	setDefaultFrom, sendmailPath                          string
	setDefaultFromRequested                               bool
	setDefaultFromAD, showDefaultFrom                     bool
	unsetDefaultFrom, noSendmailFallback                  bool
	ldapRaceCandidates                                    int
	noLDAPRace                                            bool
	authMethod                                            string
	clientCertPath, clientKeyPath, tlsCAPath, tlsRootMode string
	clientCertificate                                     *tls.Certificate
	tlsTrust                                              mail.ServerTrust
	caAllowCert, caDenyCert, caAllowSPKI, caDenySPKI      []string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cmd := newCommand()
	cmd.SetArgs(normalizeArgs(os.Args[1:]))
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "ztmail:", err)
		os.Exit(1)
	}
}

func normalizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--" {
			out = append(out, args[len(out):]...)
			return out
		}
		if arg == "-oi" {
			arg = "-i"
		}
		out = append(out, arg)
	}
	return out
}

func newCommand() *cobra.Command {
	o := options{}
	var showVersion bool
	cmd := &cobra.Command{
		Use:           "ztmail [flags] [recipient ...]",
		Short:         "Send an RFC 5322 message from stdin using SMTP and Kerberos GSSAPI",
		Long:          "A sendmail-style submission client. Defaults: mailgw.<host-domain>:25,\nAD realm <HOST-DOMAIN>, SMTP service principal smtp/<relay>, required STARTTLS.\n		On Linux, eligible GSSAPI credential or relay DNS/TCP failures can use host sendmail.\nztmail has no queue of its own; never blindly retry uncertain submissions.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, recipients []string) error {
			if showVersion {
				version, err := fullVersion()
				if err != nil {
					return err
				}
				_, err = fmt.Fprintln(cmd.OutOrStdout(), version)
				return err
			}
			o.setDefaultFromRequested = cmd.Flags().Changed("set-default-from")
			if err := validateAuthenticationFlags(cmd, o); err != nil {
				return err
			}
			if defaultSenderActionCount(o) > 0 {
				if err := validateDefaultSenderAction(o, recipients); err != nil {
					return err
				}
				if o.setDefaultFromAD {
					o.passwordPrompt = true
					if err := validateOptions(o); err != nil {
						return err
					}
				}
				return manageDefaultSender(cmd.Context(), o, cmd.OutOrStdout(), cmd.ErrOrStderr(), lookupDefaultSender)
			}
			if err := validateOptions(o); err != nil {
				return err
			}
			if o.testMode && len(recipients) != 0 {
				return errors.New("--test does not accept recipients; no email is sent")
			}
			return run(cmd.Context(), o, recipients, cmd.InOrStdin(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.authMethod, "auth", "gssapi", "SMTP authentication: gssapi, mtls (TLS certificate only), mtls-external (certificate plus AUTH EXTERNAL)")
	f.StringVar(&o.clientCertPath, "client-cert", "", "PEM client leaf certificate followed by intermediate certificates")
	f.StringVar(&o.clientKeyPath, "client-key", "", "Matching unencrypted PEM private key; owner-private on Unix")
	f.StringVar(&o.tlsCAPath, "tls-ca", "", "PEM SMTP server CA bundle (independent of LDAP and relay client-CA trust)")
	f.StringVar(&o.tlsRootMode, "tls-ca-mode", "", "SMTP server roots: system, append, replace (default: append with --tls-ca, otherwise system)")
	f.StringArrayVar(&o.caAllowCert, "tls-ca-allow-cert-sha256", nil, "Allow a server trust anchor by certificate SHA-256 (repeatable)")
	f.StringArrayVar(&o.caDenyCert, "tls-ca-deny-cert-sha256", nil, "Deny a server chain CA by certificate SHA-256 (repeatable)")
	f.StringArrayVar(&o.caAllowSPKI, "tls-ca-allow-spki-sha256", nil, "Allow a server trust anchor by public-key SHA-256 (repeatable)")
	f.StringArrayVar(&o.caDenySPKI, "tls-ca-deny-spki-sha256", nil, "Deny a server chain CA by public-key SHA-256 (repeatable)")
	f.DurationVar(&o.tlsTrust.ExpiredServerCertificateGrace, "insecure-tls-allow-expired-server-cert-for", 0, "INSECURE: server leaf expiry grace, e.g. 168h; requires replace roots on Windows/macOS")
	f.BoolVar(&o.tlsTrust.InsecureAllowUnverifiableIssuer, "insecure-tls-allow-server-certificate-with-unverifiable-issuer", false, "INSECURE: permit a signature-valid supplied server path to an untrusted anchor; other checks remain required")
	f.BoolVar(&showVersion, "version", false, "Print semantic version with UTC build time and seven-character commit SHA")
	f.BoolVar(&o.testMode, "test", false, "Report DNS/TLS and selected authentication checks; no stdin, envelope or email")
	f.BoolVar(&o.testMail, "testmail", false, "Send a generated report; GSSAPI defaults to own AD mail, mTLS needs sender/recipients; never read stdin")
	f.BoolVar(&o.debug, "debug", false, "Include observed DC reachability and runtime tables with --test or --testmail")
	f.StringVar(&o.domain, "domain", "", "Override the host DNS domain")
	f.StringVar(&o.realm, "realm", "", "Kerberos realm (default: uppercase host domain)")
	f.StringVar(&o.relay, "relay", "", "SMTP relay hostname (default: mailgw.<host-domain>)")
	f.IntVar(&o.port, "port", 25, "SMTP port; use 465 with --tls implicit")
	f.StringVar(&o.hello, "hostname", "", "EHLO hostname (default: discovered host FQDN)")
	f.StringVar(&o.spn, "spn", "", "Override the service principal, e.g. smtp/mailgw.example.com")
	f.StringVar(&o.auth, "cred-source", "auto", "Credential source: auto, keytab, ccache, sspi")
	f.BoolVar(&o.passwordPrompt, "password-prompt", false, "In auto mode, prompt for principal/password only after keytab, cache, and SSPI fail")
	f.StringVar(&o.keytab, "keytab", "", "Kerberos keytab file")
	f.StringVar(&o.principal, "principal", "", "Require this identity; otherwise try user/host account names from the keytab (not SPNs) or use the cache/SSPI identity")
	f.StringVar(&o.ccache, "ccache", "", "FILE credential cache (default on Linux: KRB5CCNAME or /tmp/krb5cc_<uid>)")
	f.StringSliceVar(&o.dnsServers, "dns-server", nil, "Numeric DNS bootstrap server(s), IP or IP:port (default: adclient OS discovery)")
	f.StringVar(&o.dnsProbeZone, "dns-probe-zone", "example.com", "External zone for optional --test/--testmail DNS failure diagnostics (not probed on success)")
	f.StringVar(&o.ldapCA, "ldap-ca", "", "Additional trusted CA bundle for verified AD LDAP TLS")
	f.IntVar(&o.ldapRaceCandidates, "ldap-race-candidates", 8, "Maximum DCs raced immediately for canonical LDAP mail lookup (1-8)")
	f.BoolVar(&o.noLDAPRace, "no-ldap-race", false, "Disable LDAP read racing; use ordinary AD server selection")
	f.StringVarP(&o.from, "from", "f", "", "Override envelope sender and From header (default: saved sender, then canonical AD mail); <> keeps null envelope and original headers")
	f.StringVar(&o.setDefaultFrom, "set-default-from", "", "Save a fully qualified default sender in the user OS config directory; do not send mail")
	f.BoolVar(&o.setDefaultFromAD, "set-default-from-ad", false, "Look up and save canonical AD mail once; prompt for a password if existing credentials fail; do not send mail")
	f.BoolVar(&o.showDefaultFrom, "show-default-from", false, "Print the saved default sender; do not read message input or contact AD")
	f.BoolVar(&o.unsetDefaultFrom, "unset-default-from", false, "Remove the saved default sender; do not send mail")
	f.BoolVar(&o.noSendmailFallback, "no-sendmail-fallback", false, "Disable Linux local-sendmail fallback when credentials or relay reachability are unavailable")
	f.StringVar(&o.sendmailPath, "sendmail-path", "", "Linux fallback sendmail executable (default: standard system locations; never this executable)")
	f.StringVarP(&o.fullName, "full-name", "F", "", "Accepted for compatibility; does not rewrite message headers")
	f.BoolVarP(&o.readHeaders, "read-recipients", "t", false, "Add To/Cc/Bcc recipients (latest Resent block if present)")
	f.BoolVarP(&o.ignoreDots, "ignore-dots", "i", false, "Do not terminate stdin at a line containing only a dot")
	f.BoolVarP(&o.verbose, "verbose", "v", false, "Print submission status and live detailed --test AD/DNS steps before the summary table, without tokens or message content")
	f.StringVar(&o.tlsMode, "tls", "required", "TLS mode: required (STARTTLS), implicit, off (no confidentiality)")
	f.DurationVar(&o.timeout, "timeout", 60*time.Second, "AD/SMTP timeout; per stage with --password-prompt (excludes message and credential input)")
	return cmd
}

func validateOptions(o options) error {
	if o.authMethod != "" && o.authMethod != "gssapi" && o.authMethod != "mtls" && o.authMethod != "mtls-external" {
		return errors.New("--auth must be gssapi, mtls, or mtls-external")
	}
	if o.ldapRaceCandidates < 1 || o.ldapRaceCandidates > 8 {
		return errors.New("--ldap-race-candidates must be between 1 and 8")
	}
	if strings.ContainsAny(o.realm, "\r\n\x00 /@") {
		return errors.New("invalid Kerberos realm")
	}
	if strings.ContainsAny(o.spn, "\r\n\x00") {
		return errors.New("invalid service principal")
	}
	for _, target := range []struct{ flag, value string }{{"relay", o.relay}, {"hostname", o.hello}} {
		if target.value != "" {
			if _, err := dnsName(target.value); err != nil {
				return fmt.Errorf("invalid --%s: %w", target.flag, err)
			}
		}
	}
	if o.sendmailPath != "" && o.noSendmailFallback {
		return errors.New("--sendmail-path conflicts with --no-sendmail-fallback")
	}
	if o.testMode && o.testMail {
		return errors.New("--test and --testmail are mutually exclusive")
	}
	if o.debug && !o.testMode && !o.testMail {
		return errors.New("--debug requires --test or --testmail")
	}
	if o.port < 1 || o.port > 65535 {
		return errors.New("--port must be between 1 and 65535")
	}
	if o.timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	switch o.tlsMode {
	case "required", "implicit", "off":
	default:
		return errors.New("--tls must be required, implicit, or off")
	}
	switch o.auth {
	case "auto", "keytab", "ccache", "sspi":
	default:
		return errors.New("--cred-source must be auto, keytab, ccache, or sspi")
	}
	if o.passwordPrompt && o.auth != "auto" {
		return errors.New("--password-prompt requires --cred-source auto; explicit credential backends do not fall back")
	}
	if o.keytab != "" && o.ccache != "" && !o.passwordPrompt {
		return errors.New("--keytab and --ccache are mutually exclusive")
	}
	if o.auth == "keytab" && o.keytab == "" {
		return errors.New("--cred-source keytab requires --keytab")
	}
	if o.keytab != "" && o.auth != "auto" && o.auth != "keytab" {
		return errors.New("--keytab conflicts with the selected --cred-source backend")
	}
	if o.ccache != "" && o.auth != "auto" && o.auth != "ccache" {
		return errors.New("--ccache conflicts with the selected --cred-source backend")
	}
	return nil
}

func run(ctx context.Context, o options, recipients []string, in io.Reader, log io.Writer) (err error) {
	parentCtx := ctx
	o, err = applyDefaultSender(o)
	if err != nil {
		return err
	}
	if o.authMethod == "" {
		o.authMethod = "gssapi"
	}
	o, err = loadAuthenticationOptions(o)
	if err != nil {
		return err
	}
	if o.authMethod != "gssapi" {
		o.noSendmailFallback = true
	}
	if o.testMode || o.testMail {
		o.report = newTestReport(log, o.verbose)
		o.report.AuthenticationMethod(mail.AuthMode(o.authMethod))
		if o.testMail {
			o.report.EnableTestMail()
		}
		if o.debug {
			o.report.EnableDebug()
		}
		defer o.report.Finish(&err)
		if o.testMail {
			o.report.Line("INFO", "Message submission", "generated diagnostic email; stdin is not read")
		} else {
			o.report.Line("INFO", "Message submission", "disabled; stdin is not read and MAIL FROM, RCPT TO, DATA are not sent")
		}
	}
	hostDone := o.report.Measure("Host/domain discovery")
	host, domain, err := discoverHost(ctx, o.domain)
	hostDone()
	o.report.Value("Hostname", host)
	o.report.Value("AD domain", domain)
	o.report.Step("Host/domain discovery", err, fmt.Sprintf("host=%q AD domain=%q", host, domain))
	if err != nil {
		if shouldFallbackToSendmail(parentCtx, o, err) {
			message, localRecipients, readErr := prepareLocalMessageContext(parentCtx, in, recipients, o.readHeaders, o.ignoreDots)
			if readErr != nil {
				return readErr
			}
			return sendmailFallback(parentCtx, o, localRecipients, message, o.from, err, log)
		}
		return err
	}
	o.domain = domain
	if o.realm == "" && o.authMethod == "gssapi" {
		o.realm = strings.ToUpper(domain)
	}
	if strings.ContainsAny(o.realm, "\r\n\x00 /@") {
		return errors.New("invalid Kerberos realm")
	}
	if o.relay == "" {
		o.relay = "mailgw." + domain
	}
	o.relay, err = dnsName(o.relay)
	if err != nil {
		return fmt.Errorf("invalid --relay: %w", err)
	}
	if o.hello == "" {
		o.hello = host
	}
	if o.hello, err = dnsName(o.hello); err != nil {
		return fmt.Errorf("invalid --hostname: %w", err)
	}
	if o.spn == "" && o.authMethod == "gssapi" {
		o.spn = "smtp/" + o.relay
	}
	if strings.ContainsAny(o.spn, "\r\n\x00") {
		return errors.New("invalid service principal")
	}
	o.report.Value("SPN", o.spn)
	if o.from != "" {
		sender, err := envelopeAddress(o.from, domain, true)
		if err != nil {
			return fmt.Errorf("envelope sender: %w", err)
		}
		if o.from != "<>" {
			o.from = sender
		}
	}
	configuredFrom := o.from
	targetDetail := fmt.Sprintf("AD domain=%q relay=%q port=%d EHLO=%q TLS=%q auth=%q",
		o.domain, o.relay, o.port, o.hello, o.tlsMode, o.authMethod)
	if o.authMethod == "gssapi" {
		targetDetail += fmt.Sprintf(" realm=%q SPN=%q cred-source=%q requested principal=%q", o.realm, o.spn, o.auth, o.principal)
	}
	o.report.Step("Target configuration", nil, targetDetail)
	o.report.Value("Target relay", fmt.Sprintf("%s:%d", o.relay, o.port))
	if o.tlsMode == "off" {
		o.report.Value("Transport security", "Disabled; no confidentiality")
	}
	var message []byte
	if o.testMail {
		for i, recipient := range recipients {
			recipients[i], err = envelopeAddress(recipient, domain, false)
			if err != nil {
				return fmt.Errorf("testmail recipient: %w", err)
			}
		}
		o.needOwnMail = true
	} else if !o.testMode {
		message, recipients, err = prepareMessageContext(ctx, in, recipients, domain, o.readHeaders, o.ignoreDots)
		if err != nil {
			return err
		}
		o.needOwnMail = len(recipients) == 0
	}
	if !o.passwordPrompt {
		work, cancel := context.WithTimeout(ctx, o.timeout)
		defer cancel()
		ctx = work
	}
	if o.authMethod != "gssapi" {
		return runCertificateSubmission(ctx, o, recipients, message, log)
	}
	adDone := o.report.Measure("AD identity and canonical mail")
	session, err := openAD(ctx, o)
	adDone()
	o.report.Step("AD identity selection", err, "credential source and identity selected")
	if err != nil {
		if shouldFallbackToSendmail(parentCtx, o, err) {
			return sendmailFallback(parentCtx, o, recipients, message, configuredFrom, err, log)
		}
		return fmt.Errorf("AD identity selection: %w", err)
	}
	sessionClosed := false
	defer func() {
		if sessionClosed {
			return
		}
		if closeErr := session.Close(); closeErr != nil {
			if err != nil || o.testMode {
				err = errors.Join(err, closeErr)
			} else {
				fmt.Fprintf(log, "Warning: message accepted, but credential cleanup failed: %v\n", closeErr)
			}
			o.report.Step("AD credential cleanup", closeErr, "")
		} else {
			o.report.Step("AD credential cleanup", nil, "credential owner closed")
		}
	}()
	if err := reportCredentialFailures(o, session, log); err != nil {
		return err
	}
	o.report.Step("Authenticated AD identity", nil, fmt.Sprintf("principal=%q realm=%q krb/gssapi source=%q canonical mail=%q",
		session.identity.Principal, session.identity.Realm, session.identity.Source, session.mail))
	o.report.Value("User", session.identity.Principal)
	o.report.Value("Cred source", string(session.identity.Source))
	from := session.mail
	if o.from != "" {
		from = o.from
	}
	o.report.Value("Mail (from)", from)
	if o.testMail {
		hostRecipientFallback := session.hostWithoutMail && len(recipients) == 0
		recipients, err = testmailRecipients(recipients, session.mail, o.from, domain, session.hostWithoutMail)
		if err != nil {
			return err
		}
		if hostRecipientFallback {
			o.report.Line("WARN", "Testmail recipient fallback", "host account has no canonical mailbox; using configured sender as testmail recipient")
		}
		o.report.Value("Canonical mail", session.mail)
		if o.from == "" {
			o.from = session.mail
		} else if o.from == "<>" {
			o.from = ""
		}
	} else if !o.testMode {
		if session.hostWithoutMail && o.from == "" {
			return errors.New("host account has no canonical AD mailbox; specify a sender with -f or save a default sender")
		}
		recipients, err = mail.RecipientFallback(recipients, session.mail, domain)
		if err != nil {
			return err
		}

		message, o.from, err = applySender(message, o.from, session.mail, domain)
		if err != nil {
			return err
		}
	}
	if o.verbose && !o.testMode {
		fmt.Fprintf(log, "Submitting to %s:%d; principal=%s; source=%s; SPN=%s; TLS=%s\n",
			o.relay, o.port, session.identity.Principal, session.identity.Source, o.spn, o.tlsMode)
	}
	if err := deliver(ctx, o, recipients, message, session, log); err != nil {
		if shouldFallbackToSendmail(parentCtx, o, err) {
			sessionClosed = true
			if closeErr := session.Close(); closeErr != nil {
				return errors.Join(err, fmt.Errorf("%w: %w", errADCleanup, closeErr))
			}
			from := o.from
			if configuredFrom == "<>" {
				from = "<>"
			}
			return sendmailFallback(parentCtx, o, recipients, message, from, err, log)
		}
		return err
	}
	if o.verbose && !o.testMode {
		fmt.Fprintln(log, "Message accepted by relay")
	}
	return nil
}

func testmailRecipients(recipients []string, canonical, configuredFrom, domain string, hostWithoutMail bool) ([]string, error) {
	if hostWithoutMail {
		if configuredFrom == "" || configuredFrom == "<>" {
			return nil, errors.New("host account has no canonical AD mailbox; testmail requires a non-null -f address or saved default sender")
		}
		address, err := envelopeAddress(configuredFrom, domain, false)
		if err != nil {
			return nil, fmt.Errorf("host testmail sender: %w", err)
		}
		if len(recipients) == 0 {
			recipients = []string{address}
		}
	}
	return mail.RecipientFallback(recipients, canonical, domain)
}
