package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func isolatedSenderConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	path, err := defaultSenderPath()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

type forbiddenReader struct{}

func (forbiddenReader) Read([]byte) (int, error) { panic("management must not read message stdin") }

func TestDefaultSenderStorageAndPrecedence(t *testing.T) {
	path := isolatedSenderConfig(t)
	if address, err := readDefaultSender(); address != "" || err != nil {
		t.Fatalf("missing default: %q, %v", address, err)
	}
	if stored, err := writeDefaultSender("User <saved@example.com>"); err != nil || stored != path {
		t.Fatalf("save: %q, %v", stored, err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "saved@example.com\n" {
		t.Fatalf("plaintext file: %q, %v", data, err)
	}
	if runtime.GOOS != "windows" {
		for _, check := range []struct {
			path string
			mode os.FileMode
		}{{path, 0600}, {filepath.Dir(path), 0700}} {
			info, err := os.Stat(check.path)
			if err != nil || info.Mode().Perm() != check.mode {
				t.Fatalf("permissions for %s: %v, %v", check.path, info, err)
			}
		}
	}
	for _, from := range []string{"", "explicit@example.com", "<>"} {
		o, err := applyDefaultSender(options{from: from})
		want := from
		if want == "" {
			want = "saved@example.com"
		}
		if err != nil || o.from != want {
			t.Fatalf("from=%q: %q, %v", from, o.from, err)
		}
	}
	if err := os.WriteFile(path, []byte("bad\nsender@example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDefaultSender(); err == nil {
		t.Fatal("corrupt config was ignored")
	}
	if _, err := applyDefaultSender(options{from: "explicit@example.com"}); err != nil {
		t.Fatalf("explicit override must bypass corrupt config: %v", err)
	}
}

func TestInvalidDefaultSenderPreservesStoredAddress(t *testing.T) {
	isolatedSenderConfig(t)
	if _, err := writeDefaultSender("saved@example.com"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "user", "<>", "a@example.com,b@example.com", "a@example.com\n", "a@example.com\x00"} {
		if _, err := writeDefaultSender(value); err == nil {
			t.Errorf("accepted invalid address %q", value)
		}
	}
	if address, err := readDefaultSender(); err != nil || address != "saved@example.com" {
		t.Fatalf("prior default changed: %q, %v", address, err)
	}
}

func TestDefaultSenderManagementDoesNotReadInput(t *testing.T) {
	path := isolatedSenderConfig(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--show-default-from"}, "No default sender configured."},
		{[]string{"--set-default-from", "User <saved@example.com>"}, "Saved default sender: saved@example.com"},
		{[]string{"--show-default-from"}, "saved@example.com"},
		{[]string{"--unset-default-from"}, "Default sender unset."},
		{[]string{"--unset-default-from"}, "Default sender unset."},
	} {
		cmd := newCommand()
		cmd.SetArgs(tc.args)
		cmd.SetIn(forbiddenReader{})
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err != nil || !strings.Contains(output.String(), tc.want) {
			t.Fatalf("%v: output=%q, err=%v", tc.args, &output, err)
		}
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unset left file: %v", err)
	}
}

func TestDefaultSenderADLookupOnceAndPreservation(t *testing.T) {
	isolatedSenderConfig(t)
	if _, err := writeDefaultSender("old@example.com"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	lookupErr := errors.New("LDAP lookup failed")
	lookup := func(_ context.Context, o options, _ io.Writer) (string, error) {
		calls++
		if !o.passwordPrompt || !o.needOwnMail || !o.setDefaultFromAD {
			t.Fatalf("AD action must permit prompting and require canonical mail: %+v", o)
		}
		return "Canonical <canonical@example.com>", lookupErr
	}
	o := options{setDefaultFromAD: true, auth: "auto"}
	if err := manageDefaultSender(context.Background(), o, io.Discard, io.Discard, lookup); !errors.Is(err, lookupErr) {
		t.Fatalf("lookup failure lost: %v", err)
	}
	if address, err := readDefaultSender(); err != nil || address != "old@example.com" {
		t.Fatalf("failed lookup replaced default: %q, %v", address, err)
	}
	lookupErr = nil
	if err := manageDefaultSender(context.Background(), o, io.Discard, io.Discard, lookup); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("want one lookup per action, got %d", calls)
	}
	if address, err := readDefaultSender(); err != nil || address != "canonical@example.com" {
		t.Fatalf("canonical default: %q, %v", address, err)
	}
}

func TestDefaultSenderActionConflicts(t *testing.T) {
	isolatedSenderConfig(t)
	for _, args := range [][]string{
		{"--set-default-from", ""},
		{"--set-default-from", "a@example.com", "--show-default-from"},
		{"--set-default-from-ad", "--unset-default-from"},
		{"--show-default-from", "recipient@example.com"},
		{"--show-default-from", "--test"},
		{"--show-default-from", "--testmail"},
		{"--show-default-from", "--debug"},
		{"--show-default-from", "-f", "a@example.com"},
		{"--show-default-from", "-t"},
		{"--set-default-from-ad", "--cred-source", "keytab", "--keytab", "missing"},
		{"--sendmail-path", "/usr/sbin/sendmail", "--no-sendmail-fallback"},
		{"--realm", "BAD REALM"},
		{"--relay", "bad/relay"},
		{"--hostname", "bad/host"},
	} {
		cmd := newCommand()
		cmd.SetArgs(args)
		cmd.SetIn(forbiddenReader{})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Execute(); err == nil {
			t.Errorf("%v: expected validation error", args)
		}
	}
}

func TestDefaultSenderFilesystemErrorsLeaveNoTemporaryFiles(t *testing.T) {
	path := isolatedSenderConfig(t)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := readDefaultSender(); err == nil {
		t.Fatal("reading a directory as config did not fail")
	}
	if _, err := writeDefaultSender("user@example.com"); err == nil {
		t.Fatal("replacing a directory as config did not fail")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != "default-from.txt" {
		t.Fatalf("temporary config files left behind: %v, %v", entries, err)
	}
}

func TestCanceledADDefaultActionPreservesPreviousSender(t *testing.T) {
	isolatedSenderConfig(t)
	if _, err := writeDefaultSender("old@example.com"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lookup := func(context.Context, options, io.Writer) (string, error) {
		cancel()
		return "new@example.com", nil
	}
	if err := manageDefaultSender(ctx, options{setDefaultFromAD: true}, io.Discard, io.Discard, lookup); !errors.Is(err, context.Canceled) {
		t.Fatalf("lookup cancellation ignored: %v", err)
	}
	if address, err := readDefaultSender(); err != nil || address != "old@example.com" {
		t.Fatalf("canceled lookup changed default: %q, %v", address, err)
	}
}
