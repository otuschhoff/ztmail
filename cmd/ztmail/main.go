package main

import (
	"context"
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
	domain, realm, relay, hello, spn string
	auth, keytab, principal, ccache  string
	dnsProbeZone, ldapCA             string
	dnsServers                       []string
	from, fullName, tlsMode          string
	port                             int
	timeout                          time.Duration
	readHeaders, ignoreDots, verbose bool
	passwordPrompt                   bool
	testMode                         bool
	debug                            bool
	needOwnMail                      bool
	report                           *testReport
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
		Long:          "A sendmail-style submission client. Defaults: mailgw.<host-domain>:25,\nAD realm <HOST-DOMAIN>, SMTP service principal smtp/<relay>, required STARTTLS.\nThis is not a queueing MTA; failed submissions must be handled by the caller.",
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
	f.BoolVar(&showVersion, "version", false, "Print semantic version with UTC build time and seven-character commit SHA")
	f.BoolVar(&o.testMode, "test", false, "Report AD/DNS/TLS/GSSAPI checks and authenticate to the relay without reading stdin or sending email")
	f.BoolVar(&o.debug, "debug", false, "Include observed DC reachability and step timing tables with --test")
	f.StringVar(&o.domain, "domain", "", "Override the host DNS domain")
	f.StringVar(&o.realm, "realm", "", "Kerberos realm (default: uppercase host domain)")
	f.StringVar(&o.relay, "relay", "", "SMTP relay hostname (default: mailgw.<host-domain>)")
	f.IntVar(&o.port, "port", 25, "SMTP port; use 465 with --tls implicit")
	f.StringVar(&o.hello, "hostname", "", "EHLO hostname (default: discovered host FQDN)")
	f.StringVar(&o.spn, "spn", "", "Override the service principal, e.g. smtp/mailgw.example.com")
	f.StringVar(&o.auth, "auth", "auto", "Credential backend: auto, keytab, ccache, sspi")
	f.BoolVar(&o.passwordPrompt, "password-prompt", false, "In auto mode, prompt for principal/password only after keytab, cache, and SSPI fail")
	f.StringVar(&o.keytab, "keytab", "", "Kerberos keytab file")
	f.StringVar(&o.principal, "principal", "", "Require this identity; otherwise try keytab principals or use the cache/SSPI identity")
	f.StringVar(&o.ccache, "ccache", "", "FILE credential cache (default on Linux: KRB5CCNAME or /tmp/krb5cc_<uid>)")
	f.StringSliceVar(&o.dnsServers, "dns-server", nil, "Numeric DNS bootstrap server(s), IP or IP:port (default: adclient OS discovery)")
	f.StringVar(&o.dnsProbeZone, "dns-probe-zone", "example.com", "External zone for optional --test DNS failure diagnostics (not probed on success)")
	f.StringVar(&o.ldapCA, "ldap-ca", "", "Additional trusted CA bundle for verified AD LDAP TLS")
	f.StringVarP(&o.from, "from", "f", "", "Override envelope sender and From header (default: principal's canonical AD mail); <> keeps null envelope and original headers")
	f.StringVarP(&o.fullName, "full-name", "F", "", "Accepted for compatibility; does not rewrite message headers")
	f.BoolVarP(&o.readHeaders, "read-recipients", "t", false, "Add To/Cc/Bcc recipients (latest Resent block if present)")
	f.BoolVarP(&o.ignoreDots, "ignore-dots", "i", false, "Do not terminate stdin at a line containing only a dot")
	f.BoolVarP(&o.verbose, "verbose", "v", false, "Print submission status and live detailed --test AD/DNS steps before the summary table, without tokens or message content")
	f.StringVar(&o.tlsMode, "tls", "required", "TLS mode: required (STARTTLS), implicit, off (no confidentiality)")
	f.DurationVar(&o.timeout, "timeout", 60*time.Second, "AD/SMTP timeout; per stage with --password-prompt (excludes message and credential input)")
	return cmd
}

func validateOptions(o options) error {
	if o.debug && !o.testMode {
		return errors.New("--debug requires --test")
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
		return errors.New("--auth must be auto, keytab, ccache, or sspi")
	}
	if o.passwordPrompt && o.auth != "auto" {
		return errors.New("--password-prompt requires --auth auto; explicit credential backends do not fall back")
	}
	if o.keytab != "" && o.ccache != "" && !o.passwordPrompt {
		return errors.New("--keytab and --ccache are mutually exclusive")
	}
	if o.auth == "keytab" && o.keytab == "" {
		return errors.New("--auth keytab requires --keytab")
	}
	if o.keytab != "" && o.auth != "auto" && o.auth != "keytab" {
		return errors.New("--keytab conflicts with the selected --auth backend")
	}
	if o.ccache != "" && o.auth != "auto" && o.auth != "ccache" {
		return errors.New("--ccache conflicts with the selected --auth backend")
	}
	return nil
}

func run(ctx context.Context, o options, recipients []string, in io.Reader, log io.Writer) (err error) {
	if o.testMode {
		o.report = newTestReport(log, o.verbose)
		if o.debug {
			o.report.EnableDebug()
		}
		defer o.report.Finish(&err)
		o.report.Line("INFO", "Message submission", "disabled; stdin is not read and MAIL FROM, RCPT TO, DATA are not sent")
	}
	hostDone := o.report.Measure("Host/domain discovery")
	host, domain, err := discoverHost(ctx, o.domain)
	hostDone()
	o.report.Value("Hostname", host)
	o.report.Value("AD domain", domain)
	o.report.Step("Host/domain discovery", err, fmt.Sprintf("host=%q AD domain=%q", host, domain))
	if err != nil {
		return err
	}
	o.domain = domain
	if o.realm == "" {
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
	if o.spn == "" {
		o.spn = "smtp/" + o.relay
	}
	if strings.ContainsAny(o.spn, "\r\n\x00") {
		return errors.New("invalid service principal")
	}
	if o.from != "" {
		sender, err := envelopeAddress(o.from, domain, true)
		if err != nil {
			return fmt.Errorf("envelope sender: %w", err)
		}
		if o.from != "<>" {
			o.from = sender
		}
	}
	o.report.Step("Target configuration", nil, fmt.Sprintf("AD domain=%q realm=%q relay=%q port=%d EHLO=%q SPN=%q TLS=%q auth=%q requested principal=%q",
		o.domain, o.realm, o.relay, o.port, o.hello, o.spn, o.tlsMode, o.auth, o.principal))
	o.report.Value("Target relay", fmt.Sprintf("%s:%d", o.relay, o.port))
	if o.tlsMode == "off" {
		o.report.Value("Transport security", "Disabled; no confidentiality")
	}
	var message []byte
	if !o.testMode {
		message, recipients, err = prepareMessage(in, recipients, domain, o.readHeaders, o.ignoreDots)
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
	adDone := o.report.Measure("AD identity and canonical mail")
	session, err := openAD(ctx, o)
	adDone()
	o.report.Step("AD identity selection", err, "credential source and identity selected")
	if err != nil {
		return fmt.Errorf("AD identity selection: %w", err)
	}
	defer func() {
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
	for _, failure := range session.failures {
		if o.report != nil {
			o.report.Line("WARN", "Skipped credential identity", failure.Error())
		} else {
			fmt.Fprintf(log, "Warning: skipped unusable AD identity: %v\n", failure)
		}
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
	if !o.testMode {
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
		return err
	}
	if o.verbose && !o.testMode {
		fmt.Fprintln(log, "Message accepted by relay")
	}
	return nil
}
