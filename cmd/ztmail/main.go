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

type commandFlags struct {
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
	setDefaultFrom, sendmailPath                          string
	setDefaultFromAD, showDefaultFrom                     bool
	unsetDefaultFrom, noSendmailFallback                  bool
	ldapRaceCandidates                                    int
	noLDAPRace                                            bool
	authMethod                                            string
	clientCertPath, clientKeyPath, tlsCAPath, tlsRootMode string
	expiredServerCertificateGrace                         time.Duration
	allowUnverifiableIssuer                               bool
	caAllowCert, caDenyCert, caAllowSPKI, caDenySPKI      []string
}

type operationOptions struct {
	commandFlags
	setDefaultFromRequested bool
	needOwnMail             bool
	report                  *testReport
	clientCertificate       *tls.Certificate
	tlsTrust                mail.ServerTrust
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
	return newCommandWithDependencies(systemDependencies())
}

func newCommandWithDependencies(deps commandDependencies) *cobra.Command {
	flags := commandFlags{}
	var showVersion bool
	cmd := &cobra.Command{
		Use:           "ztmail [flags] [recipient ...]",
		Short:         "Send an RFC 5322 message from stdin using SMTP and Kerberos GSSAPI",
		Long:          "A sendmail-style submission client. Defaults: mailgw.<host-domain>:25,\nAD realm <HOST-DOMAIN>, SMTP service principal smtp/<relay>, required STARTTLS.\n		On Linux, eligible GSSAPI credential or relay DNS/TCP failures can use host sendmail.\nztmail has no queue of its own; never blindly retry uncertain submissions.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, recipients []string) error {
			o := operationOptions{
				commandFlags: flags,
				tlsTrust: mail.ServerTrust{
					ExpiredServerCertificateGrace:   flags.expiredServerCertificateGrace,
					InsecureAllowUnverifiableIssuer: flags.allowUnverifiableIssuer,
				},
			}
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
				return manageDefaultSender(cmd.Context(), o, cmd.OutOrStdout(), cmd.ErrOrStderr(), deps.lookupDefaultSender)
			}
			if err := validateOptions(o); err != nil {
				return err
			}
			if o.testMode && len(recipients) != 0 {
				return errors.New("--test does not accept recipients; no email is sent")
			}
			return deps.run(cmd.Context(), o, recipients, cmd.InOrStdin(), cmd.ErrOrStderr())
		},
	}
	f := cmd.Flags()
	f.StringVar(&flags.authMethod, "auth", "gssapi", "SMTP authentication: gssapi, mtls (TLS certificate only), mtls-external (certificate plus AUTH EXTERNAL)")
	f.StringVar(&flags.clientCertPath, "client-cert", "", "PEM client leaf certificate followed by intermediate certificates")
	f.StringVar(&flags.clientKeyPath, "client-key", "", "Matching unencrypted PEM private key; owner-private on Unix")
	f.StringVar(&flags.tlsCAPath, "tls-ca", "", "PEM SMTP server CA bundle (independent of LDAP and relay client-CA trust)")
	f.StringVar(&flags.tlsRootMode, "tls-ca-mode", "", "SMTP server roots: system, append, replace (default: append with --tls-ca, otherwise system)")
	f.StringArrayVar(&flags.caAllowCert, "tls-ca-allow-cert-sha256", nil, "Allow a server trust anchor by certificate SHA-256 (repeatable)")
	f.StringArrayVar(&flags.caDenyCert, "tls-ca-deny-cert-sha256", nil, "Deny a server chain CA by certificate SHA-256 (repeatable)")
	f.StringArrayVar(&flags.caAllowSPKI, "tls-ca-allow-spki-sha256", nil, "Allow a server trust anchor by public-key SHA-256 (repeatable)")
	f.StringArrayVar(&flags.caDenySPKI, "tls-ca-deny-spki-sha256", nil, "Deny a server chain CA by public-key SHA-256 (repeatable)")
	f.DurationVar(&flags.expiredServerCertificateGrace, "insecure-tls-allow-expired-server-cert-for", 0, "INSECURE: server leaf expiry grace, e.g. 168h; requires replace roots on Windows/macOS")
	f.BoolVar(&flags.allowUnverifiableIssuer, "insecure-tls-allow-server-certificate-with-unverifiable-issuer", false, "INSECURE: permit a signature-valid supplied server path to an untrusted anchor; other checks remain required")
	f.BoolVar(&showVersion, "version", false, "Print semantic version with UTC build time and seven-character commit SHA")
	f.BoolVar(&flags.testMode, "test", false, "Report DNS/TLS and selected authentication checks; no stdin, envelope or email")
	f.BoolVar(&flags.testMail, "testmail", false, "Send a generated report; GSSAPI defaults to own AD mail, mTLS needs sender/recipients; never read stdin")
	f.BoolVar(&flags.debug, "debug", false, "Include observed DC reachability and runtime tables with --test or --testmail")
	f.StringVar(&flags.domain, "domain", "", "Override the host DNS domain")
	f.StringVar(&flags.realm, "realm", "", "Kerberos realm (default: uppercase host domain)")
	f.StringVar(&flags.relay, "relay", "", "SMTP relay hostname (default: mailgw.<host-domain>)")
	f.IntVar(&flags.port, "port", 25, "SMTP port; use 465 with --tls implicit")
	f.StringVar(&flags.hello, "hostname", "", "EHLO hostname (default: discovered host FQDN)")
	f.StringVar(&flags.spn, "spn", "", "Override the service principal, e.g. smtp/mailgw.example.com")
	f.StringVar(&flags.auth, "cred-source", "auto", "Credential source: auto, keytab, ccache, sspi")
	f.BoolVar(&flags.passwordPrompt, "password-prompt", false, "In auto mode, prompt for principal/password only after keytab, cache, and SSPI fail")
	f.StringVar(&flags.keytab, "keytab", "", "Kerberos keytab file")
	f.StringVar(&flags.principal, "principal", "", "Require this identity; otherwise try user/host account names from the keytab (not SPNs) or use the cache/SSPI identity")
	f.StringVar(&flags.ccache, "ccache", "", "FILE credential cache (default on Linux: KRB5CCNAME or /tmp/krb5cc_<uid>)")
	f.StringSliceVar(&flags.dnsServers, "dns-server", nil, "Numeric DNS bootstrap server(s), IP or IP:port (default: adclient OS discovery)")
	f.StringVar(&flags.dnsProbeZone, "dns-probe-zone", "example.com", "External zone for optional --test/--testmail DNS failure diagnostics (not probed on success)")
	f.StringVar(&flags.ldapCA, "ldap-ca", "", "Additional trusted CA bundle for verified AD LDAP TLS")
	f.IntVar(&flags.ldapRaceCandidates, "ldap-race-candidates", 8, "Maximum DCs raced immediately for canonical LDAP mail lookup (1-8)")
	f.BoolVar(&flags.noLDAPRace, "no-ldap-race", false, "Disable LDAP read racing; use ordinary AD server selection")
	f.StringVarP(&flags.from, "from", "f", "", "Override envelope sender and From header (default: saved sender, then canonical AD mail); <> keeps null envelope and original headers")
	f.StringVar(&flags.setDefaultFrom, "set-default-from", "", "Save a fully qualified default sender in the user OS config directory; do not send mail")
	f.BoolVar(&flags.setDefaultFromAD, "set-default-from-ad", false, "Look up and save canonical AD mail once; prompt for a password if existing credentials fail; do not send mail")
	f.BoolVar(&flags.showDefaultFrom, "show-default-from", false, "Print the saved default sender; do not read message input or contact AD")
	f.BoolVar(&flags.unsetDefaultFrom, "unset-default-from", false, "Remove the saved default sender; do not send mail")
	f.BoolVar(&flags.noSendmailFallback, "no-sendmail-fallback", false, "Disable Linux local-sendmail fallback when credentials or relay reachability are unavailable")
	f.StringVar(&flags.sendmailPath, "sendmail-path", "", "Linux fallback sendmail executable (default: standard system locations; never this executable)")
	f.StringVarP(&flags.fullName, "full-name", "F", "", "Accepted for compatibility; does not rewrite message headers")
	f.BoolVarP(&flags.readHeaders, "read-recipients", "t", false, "Add To/Cc/Bcc recipients (latest Resent block if present)")
	f.BoolVarP(&flags.ignoreDots, "ignore-dots", "i", false, "Do not terminate stdin at a line containing only a dot")
	f.BoolVarP(&flags.verbose, "verbose", "v", false, "Print submission status and live detailed --test AD/DNS steps before the summary table, without tokens or message content")
	f.StringVar(&flags.tlsMode, "tls", "required", "TLS mode: required (STARTTLS), implicit, off (no confidentiality)")
	f.DurationVar(&flags.timeout, "timeout", 60*time.Second, "AD/SMTP timeout; per stage with --password-prompt (excludes message and credential input)")
	return cmd
}

func validateOptions(o operationOptions) error {
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
	_, err := parseDNSServers(o.dnsServers)
	return err
}

func run(ctx context.Context, o operationOptions, recipients []string, in io.Reader, log io.Writer) (err error) {
	return systemDependencies().run(ctx, o, recipients, in, log)
}

func (deps commandDependencies) run(ctx context.Context, o operationOptions, recipients []string, in io.Reader, log io.Writer) (err error) {
	log = mail.TrackOutput(log)
	accepted := false
	defer func() {
		err = mail.JoinOutput(err, log, o.report, accepted || errors.Is(err, mail.ErrAcceptedOutput))
	}()
	if _, err := parseDNSServers(o.dnsServers); err != nil {
		return err
	}
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
	if outputErr := mail.CheckOutput(log, o.report, false); outputErr != nil {
		return outputErr
	}
	hostDone := o.report.Measure("Host/domain discovery")
	host, domain, err := deps.discoverHost(ctx, o.domain)
	hostDone()
	o.report.Value("Hostname", host)
	o.report.Value("AD domain", domain)
	o.report.Step("Host/domain discovery", err, fmt.Sprintf("host=%q AD domain=%q", host, domain))
	if outputErr := mail.CheckOutput(log, o.report, false); outputErr != nil {
		return mail.JoinOutput(err, log, o.report, false)
	}
	if err != nil {
		if shouldFallbackToSendmail(parentCtx, o, err) {
			message, localRecipients, readErr := prepareLocalMessageContext(parentCtx, in, recipients, o.readHeaders, o.ignoreDots)
			if readErr != nil {
				return readErr
			}
			return deps.fallback(parentCtx, o, localRecipients, message, o.from, err, log)
		}
		return err
	}
	prepared, err := prepareSubmission(ctx, o, host, domain, recipients, in, log)
	if err != nil {
		return err
	}
	o = prepared.options

	if !o.passwordPrompt {
		work, cancel := context.WithTimeout(ctx, o.timeout)
		defer cancel()
		ctx = work
	}
	if o.authMethod != "gssapi" {
		err = deps.runCertificateSubmission(ctx, o, prepared.recipients, prepared.message, log)
	} else {
		err = deps.runGSSAPISubmission(parentCtx, ctx, prepared, log)
	}
	accepted = !o.testMode && (err == nil || errors.Is(err, mail.ErrAcceptedOutput))
	return err

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
