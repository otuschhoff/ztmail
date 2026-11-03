package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/ztmail/internal/mail"
	"github.com/spf13/cobra"
)

func validateAuthenticationFlags(cmd *cobra.Command, o options) error {
	mode := o.authMethod
	if mode == "" {
		mode = "gssapi"
	}
	if mode != "gssapi" && mode != "mtls" && mode != "mtls-external" {
		return errors.New("--auth must be gssapi, mtls, or mtls-external")
	}
	if mode == "gssapi" && (o.clientCertPath != "" || o.clientKeyPath != "") {
		return errors.New("GSSAPI cannot include --client-cert or --client-key")
	}
	if mode != "gssapi" {
		for _, flag := range []string{"cred-source", "keytab", "ccache", "principal", "realm", "spn", "password-prompt", "ldap-ca", "ldap-race-candidates", "no-ldap-race", "sendmail-path"} {
			if cmd.Flags().Changed(flag) {
				return fmt.Errorf("--auth %s conflicts with explicit --%s", mode, flag)
			}
		}
		if o.clientCertPath == "" || o.clientKeyPath == "" {
			return errors.New("mTLS requires both --client-cert and --client-key")
		}
	}
	if defaultSenderActionCount(o) > 0 {
		for _, flag := range []string{"auth", "client-cert", "client-key", "tls-ca", "tls-ca-mode",
			"tls-ca-allow-cert-sha256", "tls-ca-deny-cert-sha256", "tls-ca-allow-spki-sha256", "tls-ca-deny-spki-sha256",
			"insecure-tls-allow-expired-server-cert-for", "insecure-tls-allow-server-certificate-with-unverifiable-issuer"} {
			if cmd.Flags().Changed(flag) {
				return fmt.Errorf("local/default sender management cannot include --%s", flag)
			}
		}
	}
	if o.tlsMode == "off" && (mode != "gssapi" || o.tlsCAPath != "" || o.tlsRootMode != "" ||
		len(o.caAllowCert)+len(o.caDenyCert)+len(o.caAllowSPKI)+len(o.caDenySPKI) > 0 ||
		o.tlsTrust.ExpiredServerCertificateGrace != 0 || o.tlsTrust.InsecureAllowUnverifiableIssuer) {
		return errors.New("server TLS authentication/trust options cannot be combined with --tls off")
	}
	return nil
}

func loadAuthenticationOptions(o options) (options, error) {
	var err error
	if o.clientCertPath != "" || o.clientKeyPath != "" {
		o.clientCertificate, err = mail.LoadClientCertificate(o.clientCertPath, o.clientKeyPath)
		if err != nil {
			return o, err
		}
	}
	o.tlsTrust.Mode = mail.RootMode(o.tlsRootMode)
	if o.tlsCAPath != "" {
		o.tlsTrust.Certificates, err = mail.LoadServerCAs(o.tlsCAPath)
		if err != nil {
			return o, err
		}
	}
	for _, group := range []struct {
		values []string
		kind   mail.CASelectorKind
		deny   bool
	}{
		{o.caAllowCert, mail.CACertificateSHA256, false},
		{o.caDenyCert, mail.CACertificateSHA256, true},
		{o.caAllowSPKI, mail.CASPKISHA256, false},
		{o.caDenySPKI, mail.CASPKISHA256, true},
	} {
		for _, value := range group.values {
			selector, err := mail.ParseCASelector(group.kind, value)
			if err != nil {
				return o, err
			}
			if group.deny {
				o.tlsTrust.Deny = append(o.tlsTrust.Deny, selector)
			} else {
				o.tlsTrust.Allow = append(o.tlsTrust.Allow, selector)
			}
		}
	}
	prepared, err := mail.PrepareAuthentication(mail.Config{Auth: mail.AuthMode(o.authMethod), ClientCertificate: o.clientCertificate,
		ServerTrust: o.tlsTrust, TLSMode: o.tlsMode})
	if err != nil {
		return o, err
	}
	o.clientCertificate, o.tlsTrust = prepared.ClientCertificate, prepared.ServerTrust
	return o, nil
}

func runCertificateSubmission(ctx context.Context, o options, recipients []string, message []byte, log io.Writer) (err error) {
	o.report.Value("Authentication method", o.authMethod)
	o.report.Value("Cred source", "TLS client certificate")
	if !o.testMode {
		if o.from == "" {
			return errors.New("mTLS requires -f or a saved default sender; no AD mailbox lookup is performed")
		}
		if len(recipients) == 0 {
			return errors.New("mTLS requires explicit/header recipients; sender is not a recipient fallback")
		}
		if o.testMail && o.from == "<>" {
			return errors.New("mTLS testmail requires a non-null sender")
		}
		if !o.testMail {
			message, o.from, err = applySender(message, o.from, "", o.domain)
			if err != nil {
				return err
			}
		}
		o.report.Value("Mail (from)", o.from)
	}
	settings, err := adOptionsForCredentials(o, kerberos.Options{SourceMethods: []kerberos.Source{}, PrincipalMethods: []kerberos.PrincipalMethod{}})
	if err != nil {
		return err
	}
	owner, err := adclient.NewAD(settings)
	if err != nil {
		return fmt.Errorf("create DNS-only AD owner: %w", err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if closeErr := owner.Close(cleanup); closeErr != nil {
			if err != nil || o.testMode {
				err = errors.Join(err, fmt.Errorf("DNS-only owner cleanup: %w", closeErr))
			} else {
				fmt.Fprintf(log, "Warning: message accepted, but DNS owner cleanup failed: %v\n", closeErr)
			}
		}
	}()
	return deliver(ctx, o, recipients, message, mail.ADResolver{Client: owner}, log)
}
