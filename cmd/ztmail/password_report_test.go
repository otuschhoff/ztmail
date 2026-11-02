package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/otuschhoff/adbind/ad/kerberos"
)

func TestPasswordFallbackReport(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		for _, succeeds := range []bool{false, true} {
			var output bytes.Buffer
			report := newTestReport(&output, verbose)
			report.Line("WARN", "Pre-existing warning", "retain before credential attempts")
			o := options{auth: "auto", passwordPrompt: true, verbose: verbose, report: report}
			sourceErr, passwordErr := errors.New("expired default cache"), errors.New("password rejected")
			session, err := chooseADCredentials(context.Background(), o,
				func(_ context.Context, attempt options) (*adSession, error) {
					attempt.report.Step("Acquire credential lease", sourceErr, "")
					return nil, sourceErr
				},
				func(_ context.Context, attempt options) (*adSession, error) {
					if !succeeds {
						attempt.report.Step("Acquire credential lease", passwordErr, "")
						return nil, passwordErr
					}
					attempt.report.Line("WARN", "Password attempt warning", "retain password-stage warning")
					return &adSession{identity: kerberos.Identity{Source: kerberos.SourcePassword}}, nil
				})
			if succeeds {
				if err != nil {
					t.Fatal(err)
				}
				if len(session.failures) == 0 || !errors.Is(session.failures[0], sourceErr) {
					t.Fatal("source failure was discarded instead of retained for diagnostics")
				}
				reportCredentialFailures(o, session, &output)
				report.Step("SMTP AUTH GSSAPI", errors.New("SMTP rejected"), "")
			} else if !errors.Is(err, sourceErr) || !errors.Is(err, passwordErr) {
				t.Fatalf("fallback failure lost causes: %v", err)
			}
			report.Finish(&err)
			result := output.String()
			if strings.Contains(result, sourceErr.Error()) != (verbose || !succeeds) {
				t.Errorf("verbose=%t success=%t: wrong recovered-issue visibility:\n%s", verbose, succeeds, result)
			}
			for _, want := range []string{"Pre-existing warning", "retain before credential attempts"} {
				if !strings.Contains(result, want) {
					t.Errorf("lost unrelated diagnostic %q:\n%s", want, result)
				}
			}
			if succeeds && (!strings.Contains(result, "retain password-stage warning") ||
				!strings.Contains(result, "SMTP rejected")) {
				t.Fatalf("recovery hid current or later failures:\n%s", result)
			}
		}
	}
}

func TestPasswordFallbackSendWarnings(t *testing.T) {
	for _, source := range []kerberos.Source{kerberos.SourcePassword, kerberos.SourceKeytab} {
		for _, verbose := range []bool{false, true} {
			var output bytes.Buffer
			reportCredentialFailures(options{passwordPrompt: true, verbose: verbose},
				&adSession{identity: kerberos.Identity{Source: source}, failures: []error{errors.New("source failed")}}, &output)
			wantWarning := source != kerberos.SourcePassword || verbose
			if strings.Contains(output.String(), "source failed") != wantWarning {
				t.Errorf("source=%s verbose=%t: incorrect output %q", source, verbose, output.String())
			}
		}
	}
}

func TestPasswordFallbackOutputErrorRemainsVisible(t *testing.T) {
	writeErr := errors.New("report output failed")
	report := newTestReport(brokenPromptReportWriter{writeErr}, true)
	start := report.IssueCheckpoint()
	report.Line("FAIL", "Acquire credential lease", "expired cache")
	end := report.IssueCheckpoint()
	report.RecoverIssues(start, end)
	var err error
	report.Finish(&err)
	if !errors.Is(err, writeErr) {
		t.Fatalf("lost report-writing error: %v", err)
	}
}

type brokenPromptReportWriter struct{ err error }

func (w brokenPromptReportWriter) Write([]byte) (int, error) { return 0, w.err }
