package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/adbind/ad/kerberos/keytab"
	"golang.org/x/term"
)

type passwordTerminal interface {
	io.Reader
	io.Writer
	ReadPassword() ([]byte, error)
	Close() error
}

type consoleTerminal struct {
	input, output *os.File
}

func (t *consoleTerminal) Read(p []byte) (int, error)  { return t.input.Read(p) }
func (t *consoleTerminal) Write(p []byte) (int, error) { return t.output.Write(p) }
func (t *consoleTerminal) ReadPassword() ([]byte, error) {
	return term.ReadPassword(int(t.input.Fd()))
}
func (t *consoleTerminal) Close() error {
	err := t.input.Close()
	if t.input != t.output {
		err = errors.Join(err, t.output.Close())
	}
	return err
}

func openADPassword(ctx context.Context, o options) (*adSession, error) {
	// Build the common AD configuration before asking for a secret.
	settings, err := adOptionsForCredentials(o, kerberos.Options{Source: kerberos.SourcePassword, Realm: o.realm})
	if err != nil {
		return nil, err
	}
	explicit := o.principal
	guess := explicit
	if guess == "" {
		current, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("cannot guess the current user principal; specify --principal: %w", err)
		}
		guess = guessedPrincipal(current.Username, o.realm)
	}
	guess, err = promptPrincipal(guess, o.realm)
	if err != nil {
		return nil, err
	}
	terminal, err := openPasswordTerminal()
	if err != nil {
		return nil, fmt.Errorf("password fallback requires a controlling terminal; message stdin is never used for credentials: %w", err)
	}
	principal, password, promptErr := readPasswordCredentials(ctx, terminal, guess, explicit != "", o.realm)
	closeErr := terminal.Close()
	if promptErr != nil || closeErr != nil {
		clear(password)
		return nil, errors.Join(promptErr, closeErr)
	}
	defer clear(password)
	settings.Credentials = kerberos.Options{Source: kerberos.SourcePassword,
		Principal: principal, Realm: o.realm, Password: string(password), Hooks: settings.Credentials.Hooks}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	return openADAttempt(ctx, o, settings)
}

func guessedPrincipal(username, realm string) string {
	if separator := strings.LastIndexAny(username, `\/`); separator >= 0 {
		username = username[separator+1:]
	}
	username, _, _ = strings.Cut(username, "@")
	return username + "@" + strings.ToUpper(realm)
}

func promptPrincipal(principal, realm string) (string, error) {
	if !strings.Contains(principal, "@") {
		principal += "@" + strings.ToUpper(realm)
	}
	components, err := keytab.ParsePrincipal(principal, realm)
	if err != nil {
		return "", fmt.Errorf("invalid password principal; use user@%s: %w", realm, err)
	}
	return strings.Join(components, "/") + "@" + strings.ToUpper(realm), nil
}

func readPasswordCredentials(ctx context.Context, terminal passwordTerminal, guess string, pinned bool, realm string) (principal string, password []byte, err error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if _, err := fmt.Fprintln(terminal, "Existing credential methods failed. Requesting a Kerberos TGT with a password."); err != nil {
		return "", nil, err
	}
	principal = guess
	if pinned {
		if _, err := fmt.Fprintf(terminal, "Kerberos principal (--principal): %s\n", principal); err != nil {
			return "", nil, err
		}
	} else {
		if _, err := fmt.Fprintf(terminal, "Kerberos principal [%s] (Enter to accept or type a replacement): ", guess); err != nil {
			return "", nil, err
		}
		input, err := readPrincipalLine(ctx, terminal)
		if err != nil {
			return "", nil, fmt.Errorf("read principal: %w", err)
		}
		if input != "" {
			principal = input
		}
	}
	principal, err = promptPrincipal(principal, realm)
	if err != nil {
		return "", nil, err
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if _, err := fmt.Fprintf(terminal, "Password for %s: ", principal); err != nil {
		return "", nil, err
	}
	password, err = terminal.ReadPassword()
	_, newlineErr := fmt.Fprintln(terminal)
	err = errors.Join(err, newlineErr, ctx.Err())
	if err == nil && len(password) == 0 {
		err = errors.New("empty password is not allowed")
	}
	if err != nil {
		clear(password)
		return "", nil, fmt.Errorf("read password: %w", err)
	}
	return principal, password, nil
}

func readPrincipalLine(ctx context.Context, input io.Reader) (string, error) {
	var line []byte
	var b [1]byte
	for len(line) <= 1024 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := input.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				return strings.TrimSuffix(string(line), "\r"), nil
			}
			line = append(line, b[0])
		}
		if err != nil {
			return "", err
		}
		if n == 0 {
			return "", io.ErrNoProgress
		}
	}
	return "", errors.New("principal exceeds 1024 bytes")
}
