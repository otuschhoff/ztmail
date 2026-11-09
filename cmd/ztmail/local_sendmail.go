package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/ztmail/internal/mail"
)

const nativeFallbackEnvironment = "ZTMAIL_SENDMAIL_FALLBACK"

func shouldFallbackToSendmail(ctx context.Context, o options, err error) bool {
	if runtime.GOOS != "linux" || (o.authMethod != "" && o.authMethod != "gssapi") || o.noSendmailFallback || o.testMode || o.testMail || o.setDefaultFromAD ||
		os.Getenv(nativeFallbackEnvironment) == "1" ||
		ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, mail.ErrDeliveryUncertain) ||
		errors.Is(err, errADCleanup) || errors.Is(err, kerberos.ErrClosed) || errors.Is(err, kerberos.ErrCapacity) ||
		errors.Is(err, kerberos.ErrCredentialsChanged) || errors.Is(err, errADNonCredentialFailure) ||
		errors.Is(err, errADPasswordFailure) {
		return false
	}
	return errors.Is(err, errADCredentialsUnavailable) || errors.Is(err, errHostDomainUnavailable) ||
		errors.Is(err, mail.ErrRelayUnavailable)
}

func findLocalSendmail(candidates []string, currentExecutable string) (string, error) {
	self, err := os.Stat(currentExecutable)
	if err != nil {
		return "", fmt.Errorf("identify current executable: %w", err)
	}
	var failures []error
	for _, candidate := range candidates {
		path, err := filepath.Abs(candidate)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", path, err))
			continue
		}
		if os.SameFile(self, info) {
			failures = append(failures, fmt.Errorf("%s resolves to this executable; refusing recursive fallback", path))
			continue
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			failures = append(failures, fmt.Errorf("%s is not an executable regular file", path))
			continue
		}
		return path, nil
	}
	return "", errors.Join(append([]error{errors.New("no usable host sendmail executable")}, failures...)...)
}

func localSendmailPath(override string) (string, error) {
	candidates := []string{"/usr/sbin/sendmail", "/usr/lib/sendmail", "/sbin/sendmail", "/usr/libexec/sendmail"}
	if override != "" {
		candidates = []string{override}
	}
	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate current executable: %w", err)
	}
	return findLocalSendmail(candidates, self)
}

func submitLocalSendmail(ctx context.Context, executable, from string, recipients []string, message []byte, log io.Writer) error {
	if len(recipients) == 0 {
		return errors.New("local sendmail fallback needs recipients in arguments or headers; AD self-recipient lookup is unavailable")
	}
	for _, recipient := range recipients {
		address, err := mail.LocalEnvelopeAddress(recipient)
		if err != nil {
			return fmt.Errorf("native recipient: %w", err)
		}
		if address != recipient {
			return errors.New("native recipient must be a bare mailbox or local alias")
		}
	}
	args := []string{"-i"}
	if from != "" {
		args = append(args, "-f", from)
	}
	args = append(args, "--")
	args = append(args, recipients...)
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = time.Second
	cmd.Env = append(os.Environ(), nativeFallbackEnvironment+"=1")
	cmd.Stdin = bytes.NewReader(message)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start host sendmail: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("%w: host sendmail failed; do not blindly retry: %w", mail.ErrDeliveryUncertain, errors.Join(err, ctx.Err()))
	}
	return nil
}

func sendmailFallback(ctx context.Context, o options, recipients []string, message []byte, from string, cause error, log io.Writer) error {
	if !shouldFallbackToSendmail(ctx, o, cause) {
		return fmt.Errorf("host sendmail fallback is not permitted: %w", cause)
	}
	if from != "" {
		var err error
		message, _, err = applySender(message, from, "", o.domain)
		if err != nil {
			return errors.Join(cause, fmt.Errorf("fallback sender: %w", err))
		}
	}
	executable, err := localSendmailPath(o.sendmailPath)
	if err != nil {
		return errors.Join(cause, err)
	}
	reason := "Kerberos credentials or host AD domain unavailable"
	if errors.Is(cause, mail.ErrRelayUnavailable) {
		reason = "Mail relay unreachable"
	}
	if _, err := fmt.Fprintf(log, "Warning: %s; using host sendmail %s.\n", reason, executable); err != nil {
		return errors.Join(cause, fmt.Errorf("report sendmail fallback: %w", err))
	}
	if o.verbose {
		if _, err := fmt.Fprintf(log, "Primary submission failed: %v\n", cause); err != nil {
			return errors.Join(cause, fmt.Errorf("report primary submission failure: %w", err))
		}
	}
	work, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	if err := submitLocalSendmail(work, executable, from, recipients, message, log); err != nil {
		return errors.Join(cause, err)
	}
	if o.verbose {
		if _, err := fmt.Fprintln(log, "Message accepted by host sendmail (local acceptance, not mailbox delivery proof)."); err != nil {
			return fmt.Errorf("%w: local submission succeeded but status output failed: %w", mail.ErrDeliveryUncertain, err)
		}
	}
	return nil
}
