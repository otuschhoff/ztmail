package main

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/ztmail/internal/mail"
)

type credentialStageWriter struct {
	failAt string
	err    error
}

func (w credentialStageWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.failAt) {
		return 0, w.err
	}
	return len(p), nil
}

func TestCredentialOutputFailureStopsAcquisitionAndFallback(t *testing.T) {
	writeErr, sourceErr := errors.New("required credential report failed"), errors.New("credential unavailable")
	for _, mode := range []string{"before-source", "inside-source", "not-opted-in"} {
		t.Run(mode, func(t *testing.T) {
			report := newTestReport(credentialStageWriter{failAt: "Injected", err: writeErr}, true)
			if mode != "inside-source" {
				report.Line("WARN", "Injected", "already failed")
			}
			sources, passwords := 0, 0
			_, err := chooseADCredentials(t.Context(), operationOptions{commandFlags: commandFlags{keytab: "synthetic", passwordPrompt: mode != "not-opted-in"}, report: report},
				func(context.Context, operationOptions) (*adSession, error) {
					sources++
					report.Line("FAIL", "Injected", "source failed")
					return nil, sourceErr
				},
				func(context.Context, operationOptions) (*adSession, error) {
					passwords++
					return &adSession{}, nil
				})
			wantSources := 0
			if mode == "inside-source" {
				wantSources = 1
				if !errors.Is(err, sourceErr) {
					t.Errorf("independent source cause lost: %v", err)
				}
			}
			if sources != wantSources || passwords != 0 || !errors.Is(err, writeErr) || !errors.Is(err, mail.ErrOutputFailed) {
				t.Fatalf("output failure allowed credential work/fallback: sources=%d passwords=%d err=%v", sources, passwords, err)
			}
			if strings.Count(err.Error(), writeErr.Error()) != 1 {
				t.Fatalf("repeated credential output cause: %v", err)
			}
		})
	}
}

func TestPrincipalOutputFailureStopsFallback(t *testing.T) {
	writeErr := errors.New("required principal output failed")
	report := newTestReport(credentialStageWriter{failAt: "Injected", err: writeErr}, true)
	report.Line("FAIL", "Injected", "failed")
	outputErr := mail.CheckOutput(nil, report, false)
	attempts := 0
	_, err := selectADSession(t.Context(), []string{"one@CORP.EXAMPLE", "two@CORP.EXAMPLE"},
		func(context.Context, string) (*adSession, error) {
			attempts++
			return nil, outputErr
		})
	if attempts != 1 || !errors.Is(err, writeErr) || !errors.Is(err, mail.ErrOutputFailed) {
		t.Fatalf("output failure retried a principal: attempts=%d err=%v", attempts, err)
	}
}

func TestADAttemptOutputFailureBeforeCredentialAcquisition(t *testing.T) {
	for _, step := range []string{"AD identity attempt", "AD client configuration"} {
		t.Run(step, func(t *testing.T) {
			t.Setenv("KRB5_CONFIG", filepath.Join(t.TempDir(), "absent-config"))
			writeErr := errors.New("required AD setup output failed")
			report := newTestReport(credentialStageWriter{failAt: step, err: writeErr}, true)
			o := operationOptions{commandFlags: commandFlags{domain: "corp.example", realm: "CORP.EXAMPLE", dnsProbeZone: "example.com"}, report: report}
			settings, err := adOptionsForCredentials(o, kerberos.Options{Source: kerberos.SourceCCache,
				CCache: filepath.Join(t.TempDir(), "absent-cache"), Principal: "alice@CORP.EXAMPLE", Realm: o.realm})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			session, err := openADAttempt(ctx, o, settings)
			if session != nil {
				if closeErr := session.Close(); closeErr != nil {
					t.Error(closeErr)
				}
				t.Fatal("returned an owned session after required output failure")
			}
			if !errors.Is(err, writeErr) || !errors.Is(err, mail.ErrOutputFailed) || errors.Is(err, errADCredentialsUnavailable) {
				t.Fatalf("credential acquisition ran after failed setup output: %v", err)
			}
			if strings.Count(err.Error(), writeErr.Error()) != 1 {
				t.Fatalf("repeated setup/cleanup output cause: %v", err)
			}
		})
	}
}

type shortPasswordTerminal struct {
	*fakePasswordTerminal
	writes, failAt int
}

func (f *shortPasswordTerminal) Write(p []byte) (int, error) {
	f.writes++
	if f.writes == f.failAt {
		return len(p) - 1, nil
	}
	return f.fakePasswordTerminal.Write(p)
}

func TestPasswordPromptShortWritesStopAndClearSecrets(t *testing.T) {
	for _, step := range []struct {
		name string
		nth  int
	}{{"notice", 1}, {"principal", 2}, {"password-prompt", 3}, {"newline", 4}} {
		t.Run(step.name, func(t *testing.T) {
			secret := []byte("synthetic-secret")
			terminal := &shortPasswordTerminal{fakePasswordTerminal: &fakePasswordTerminal{
				input: strings.NewReader(""), password: secret}, failAt: step.nth}
			_, password, err := readPasswordCredentials(t.Context(), terminal, "alice@CORP.EXAMPLE", true, "CORP.EXAMPLE", nil)
			if !errors.Is(err, io.ErrShortWrite) || password != nil {
				t.Fatalf("short prompt write ignored: err=%v password-returned=%t", err, password != nil)
			}
			wantReads := 0
			if step.nth == 4 {
				wantReads = 1
				for _, b := range secret {
					if b != 0 {
						t.Fatal("password retained after failed trailing output")
					}
				}
			}
			if terminal.passwordReads != wantReads || terminal.writes != step.nth || terminal.principalReads != 0 {
				t.Fatalf("continued input/output after short write: %+v", terminal)
			}
		})
	}
}

func TestCredentialWarningDirectShortWrite(t *testing.T) {
	terminal := &shortPasswordTerminal{fakePasswordTerminal: &fakePasswordTerminal{}, failAt: 1}
	err := reportCredentialFailures(operationOptions{}, &adSession{failures: []error{errors.New("skipped"), errors.New("next")}}, terminal)
	if !errors.Is(err, io.ErrShortWrite) || terminal.writes != 1 {
		t.Fatalf("required skipped-identity output was lost/retried: err=%v writes=%d", err, terminal.writes)
	}
}
