package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func defaultSenderPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user configuration directory: %w", err)
	}
	return filepath.Join(dir, "ztmail", "default-from.txt"), nil
}

func defaultSenderAddress(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("default sender contains a forbidden control character")
	}
	value = strings.TrimSpace(value)
	if !strings.Contains(value, "@") {
		return "", errors.New("default sender must be a fully qualified mailbox, e.g. user@example.com")
	}
	address, err := envelopeAddress(value, "", false)
	if err != nil {
		return "", fmt.Errorf("default sender: %w", err)
	}
	return address, nil
}

func readDefaultSender() (string, error) {
	path, err := defaultSenderPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read default sender %q: %w", path, err)
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	address, err := defaultSenderAddress(value)
	if err != nil {
		return "", fmt.Errorf("invalid default sender file %q: %w", path, err)
	}
	return address, nil
}

func writeDefaultSender(value string) (path string, err error) {
	address, err := defaultSenderAddress(value)
	if err != nil {
		return "", err
	}
	path, err = defaultSenderPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", fmt.Errorf("create default sender directory: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".default-from-*")
	if err != nil {
		return "", fmt.Errorf("create default sender file: %w", err)
	}
	tempPath := file.Name()
	defer func() {
		if removeErr := os.Remove(tempPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temporary default sender file: %w", removeErr))
		}
	}()
	_, writeErr := io.WriteString(file, address+"\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if fileErr := errors.Join(writeErr, file.Close()); fileErr != nil {
		return "", fmt.Errorf("write default sender file: %w", fileErr)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return "", fmt.Errorf("replace default sender file: %w", err)
	}
	return path, nil
}

func defaultSenderActionCount(o options) int {
	count := 0
	for _, selected := range []bool{o.setDefaultFromRequested, o.setDefaultFromAD, o.showDefaultFrom, o.unsetDefaultFrom} {
		if selected {
			count++
		}
	}
	return count
}

func validateDefaultSenderAction(o options, recipients []string) error {
	if defaultSenderActionCount(o) != 1 {
		return errors.New("default sender set, AD lookup, show and unset actions are mutually exclusive")
	}
	if len(recipients) != 0 || o.testMode || o.testMail || o.debug {
		return errors.New("default sender management does not accept recipients, --test, --testmail or --debug")
	}
	if o.from != "" || o.readHeaders {
		return errors.New("default sender management does not accept -f or -t")
	}
	if o.setDefaultFromAD && o.auth != "auto" {
		return errors.New("--set-default-from-ad requires --cred-source auto to permit password fallback")
	}
	return nil
}

func manageDefaultSender(ctx context.Context, o options, out, log io.Writer,
	lookup func(context.Context, options, io.Writer) (string, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.showDefaultFrom {
		address, err := readDefaultSender()
		if err != nil {
			return err
		}
		if address == "" {
			address = "No default sender configured."
		}
		_, err = fmt.Fprintln(out, address)
		return err
	}
	if o.unsetDefaultFrom {
		path, err := defaultSenderPath()
		if err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("unset default sender %q: %w", path, err)
		}
		_, err = fmt.Fprintln(out, "Default sender unset.")
		return err
	}
	address := o.setDefaultFrom
	if o.setDefaultFromAD {
		o.passwordPrompt, o.needOwnMail = true, true
		var err error
		address, err = lookup(ctx, o, log)
		if err != nil {
			return fmt.Errorf("look up default sender from AD: %w", err)
		}
	}
	address, err := defaultSenderAddress(address)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	path, err := writeDefaultSender(address)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Saved default sender: %s\nFile: %s\n", address, path)
	return err
}

func lookupDefaultSender(ctx context.Context, o options, log io.Writer) (string, error) {
	_, domain, err := discoverHost(ctx, o.domain)
	if err != nil {
		return "", err
	}
	o.domain = domain
	if o.realm == "" {
		o.realm = strings.ToUpper(domain)
	}
	if strings.ContainsAny(o.realm, "\r\n\x00 /@") {
		return "", errors.New("invalid Kerberos realm")
	}
	session, err := openAD(ctx, o)
	if err != nil {
		return "", err
	}
	address := session.mail
	if err := session.Close(); err != nil {
		return "", fmt.Errorf("close AD owner after default sender lookup: %w", err)
	}
	if err := reportCredentialFailures(o, session, log); err != nil {
		return "", err
	}
	return defaultSenderAddress(address)
}

func applyDefaultSender(o options) (options, error) {
	if o.from != "" {
		return o, nil
	}
	address, err := readDefaultSender()
	if err != nil {
		return o, err
	}
	o.from = address
	return o, nil
}
