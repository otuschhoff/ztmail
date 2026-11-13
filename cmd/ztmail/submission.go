package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/otuschhoff/ztmail/internal/mail"
)

type preparedSubmission struct {
	options    operationOptions
	recipients []string
	message    []byte
}

func prepareSubmission(ctx context.Context, o operationOptions, host, domain string, recipients []string, in io.Reader, log io.Writer) (preparedSubmission, error) {
	var err error
	o.commandFlags, err = resolveTarget(o.commandFlags, host, domain)
	if err != nil {
		return preparedSubmission{}, err
	}
	o.report.Value("SPN", o.spn)
	if o.from != "" {
		sender, err := envelopeAddress(o.from, domain, true)
		if err != nil {
			return preparedSubmission{}, fmt.Errorf("envelope sender: %w", err)
		}
		if o.from != "<>" {
			o.from = sender
		}
	}
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
	if outputErr := mail.CheckOutput(log, o.report, false); outputErr != nil {
		return preparedSubmission{}, outputErr
	}
	var message []byte
	if o.testMail {
		for i, recipient := range recipients {
			recipients[i], err = envelopeAddress(recipient, domain, false)
			if err != nil {
				return preparedSubmission{}, fmt.Errorf("testmail recipient: %w", err)
			}
		}
		o.needOwnMail = true
	} else if !o.testMode {
		message, recipients, err = prepareMessageContext(ctx, in, recipients, domain, o.readHeaders, o.ignoreDots)
		if err != nil {
			return preparedSubmission{}, err
		}
		o.needOwnMail = len(recipients) == 0
	}
	return preparedSubmission{options: o, recipients: recipients, message: message}, nil
}

func (deps commandDependencies) runGSSAPISubmission(parentCtx, ctx context.Context, submission preparedSubmission, log io.Writer) (err error) {
	o, recipients, message := submission.options, submission.recipients, submission.message
	configuredFrom := o.from
	adDone := o.report.Measure("AD identity and canonical mail")
	session, err := deps.openAD(ctx, o)
	adDone()
	o.report.Step("AD identity selection", err, "credential source and identity selected")
	if outputErr := mail.CheckOutput(log, o.report, false); outputErr != nil {
		if session != nil {
			return mail.JoinOutput(errors.Join(err, session.Close()), log, o.report, false)
		}
		return mail.JoinOutput(err, log, o.report, false)
	}
	if err != nil {
		if shouldFallbackToSendmail(parentCtx, o, err) {
			return deps.fallback(parentCtx, o, recipients, message, configuredFrom, err, log)
		}
		return fmt.Errorf("AD identity selection: %w", err)
	}
	sessionClosed := false
	defer func() {
		if sessionClosed {
			return
		}
		if closeErr := session.Close(); closeErr != nil {
			o.report.Step("AD credential cleanup", closeErr, "")
			if err != nil || o.testMode {
				err = errors.Join(err, closeErr)
			} else {
				err = reportAcceptedCleanup(log, o.report, "credential", closeErr)
			}
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
		recipients, err = testmailRecipients(recipients, session.mail, o.from, o.domain, session.hostWithoutMail)
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
		recipients, err = mail.RecipientFallback(recipients, session.mail, o.domain)
		if err != nil {
			return err
		}

		message, o.from, err = applySender(message, o.from, session.mail, o.domain)
		if err != nil {
			return err
		}
	}
	if o.verbose && !o.testMode {
		fmt.Fprintf(log, "Submitting to %s:%d; principal=%s; source=%s; SPN=%s; TLS=%s\n",
			o.relay, o.port, session.identity.Principal, session.identity.Source, o.spn, o.tlsMode)
	}
	if outputErr := mail.CheckOutput(log, o.report, false); outputErr != nil {
		return outputErr
	}
	if err := deps.deliver(ctx, o, recipients, message, session, log); err != nil {
		if shouldFallbackToSendmail(parentCtx, o, err) {
			sessionClosed = true
			if closeErr := session.Close(); closeErr != nil {
				return errors.Join(err, fmt.Errorf("%w: %w", errADCleanup, closeErr))
			}
			from := o.from
			if configuredFrom == "<>" {
				from = "<>"
			}
			return deps.fallback(parentCtx, o, recipients, message, from, err, log)
		}
		return err
	}
	if o.verbose && !o.testMode {
		fmt.Fprintln(log, "Message accepted by relay")
	}
	return nil
}
