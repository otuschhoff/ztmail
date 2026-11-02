package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/dns"
	"github.com/otuschhoff/adbind/ad/observe"
)

func TestTestFlagDoesNotReadStdin(t *testing.T) {
	cmd := newCommand()
	cmd.SetArgs([]string{"--test", "--domain", "corp.example", "--keytab", filepath.Join(t.TempDir(), "missing"), "-t", "-v"})
	cmd.SetIn(failingReader{})
	var output bytes.Buffer
	cmd.SetErr(&output)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "inspect keytab") {
		t.Fatalf("expected credential failure without consuming stdin: %v", err)
	}
	for _, expected := range []string{
		"[OK] Host/domain discovery", `AD domain="corp.example"`, `realm="CORP.EXAMPLE"`,
		`relay="mailgw.corp.example"`, `SPN="smtp/mailgw.corp.example"`, `source="keytab"`,
		"[FAIL] Keytab inspection", "[FAIL] Test", "stdin is not read",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in %s", expected, &output)
		}
	}
	if strings.Contains(output.String(), "Message accepted") {
		t.Fatal("test mode claimed to send a message")
	}
}

func TestTestFlagRejectsRecipients(t *testing.T) {
	cmd := newCommand()
	cmd.SetArgs([]string{"--test", "recipient@corp.example"})
	cmd.SetIn(failingReader{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "does not accept recipients") {
		t.Fatalf("expected recipient validation error: %v", err)
	}
}

func TestEndpointReportIsConcurrentAndServerAttributed(t *testing.T) {
	var output bytes.Buffer
	report := newTestReport(&output, true)
	var wg sync.WaitGroup
	for _, protocol := range []string{"dns", "kerberos", "ldap"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				report.Exchange(context.Background(), observe.ExchangeEvent{Protocol: protocol, Request: "synthetic-request",
					Server: "dc.corp.example:88", Address: "192.0.2.10:88", Transport: "tcp",
					Outcome: observe.Success, Duration: time.Millisecond})
			}
		}()
	}
	wg.Wait()
	var err error
	report.Finish(&err)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	for _, expected := range []string{`protocol="dns"`, `protocol="kerberos"`, `protocol="ldap"`,
		`server="dc.corp.example:88"`, `peer="192.0.2.10:88"`, `transport="tcp"`,
		"not authentication proof", "Windows SSPI", "Cache hits", "30 AD exchanges"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q", expected)
		}
	}
}

func TestDiagnosticHooksAreOptInAndPreserveSDKRouting(t *testing.T) {
	o := options{auth: "auto", domain: "corp.example", realm: "CORP.EXAMPLE", dnsProbeZone: "example.com",
		ccache: filepath.Join(t.TempDir(), "cache")}
	settings, err := adOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Hooks.Exchange != nil || settings.Credentials.Hooks.Exchange != nil || settings.DNSSummary != nil ||
		settings.DNS.DNS.Summary != nil {
		t.Fatal("diagnostics were enabled without --test")
	}
	var output bytes.Buffer
	o.report = newTestReport(&output, false)
	settings, err = adOptions(o)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Credentials.KDCProvider != nil || settings.Credentials.DialContext != nil ||
		settings.DialContext != nil || settings.Discovery.DialContext != nil {
		t.Fatal("diagnostics replaced SDK-managed network routing")
	}
	if settings.Hooks.Exchange == nil || settings.Credentials.Hooks.Observe == nil || settings.Discovery.Hooks.Observe == nil ||
		settings.DNSSummary == nil {
		t.Fatal("shared/credential/discovery hooks were not wired")
	}
	if settings.Credentials.Hooks.Exchange != nil || settings.Discovery.Hooks.Exchange != nil ||
		settings.DNS.DNS.Summary != nil || settings.DNS.DNS.DialContext != nil {
		t.Fatal("leaf exchange hooks would duplicate SDK-forwarded observations")
	}
	settings.Hooks.Exchange(context.Background(), observe.ExchangeEvent{Protocol: "ldap", Outcome: observe.Success})
	if !strings.Contains(output.String(), `protocol="ldap"`) {
		t.Fatal("hook was not connected to the report")
	}
	settings.DNSSummary(dns.SummaryEvent{Name: "mailgw.corp.example", Outcome: dns.SummaryFailed})
	if strings.Count(output.String(), "] DNS:") != 1 || !strings.Contains(output.String(), `[FAIL] DNS: name="mailgw.corp.example"`) {
		t.Fatalf("DNS summary hook was not connected exactly once: %s", &output)
	}
}

func TestTestFlagWiresDNSVerbosity(t *testing.T) {
	original := newTestReport
	t.Cleanup(func() { newTestReport = original })
	for _, verbose := range []bool{false, true} {
		t.Run(fmt.Sprint(verbose), func(t *testing.T) {
			newTestReport = func(output io.Writer, enabled bool) *testReport {
				if enabled != verbose {
					t.Errorf("report verbose=%v, want %v", enabled, verbose)
				}
				report := original(output, enabled)
				report.DNSSummary(dns.SummaryEvent{Name: "mailgw.corp.example", Outcome: dns.SummaryFailed})
				report.Exchange(context.Background(), observe.ExchangeEvent{Protocol: "dns", Outcome: observe.Success})
				return report
			}
			cmd := newCommand()
			args := []string{"--test", "--domain", "corp.example", "--keytab", filepath.Join(t.TempDir(), "missing")}
			if verbose {
				args = append(args, "--verbose")
			}
			cmd.SetArgs(args)
			cmd.SetIn(failingReader{})
			var output bytes.Buffer
			cmd.SetErr(&output)
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "inspect keytab") {
				t.Fatalf("expected keytab failure without reading stdin: %v", err)
			}
			if !strings.Contains(output.String(), "[FAIL] DNS:") ||
				strings.Contains(output.String(), `protocol="dns"`) != verbose {
				t.Fatalf("incorrect DNS verbosity:\n%s", &output)
			}
		})
	}
}

type failedReportWriter struct{ err error }

func (w failedReportWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDiagnosticOutputFailureIsReturned(t *testing.T) {
	writeErr := errors.New("diagnostic output failed")
	report := newTestReport(failedReportWriter{writeErr}, false)
	report.Step("Synthetic step", nil, "completed")
	original := errors.New("authentication failed")
	err := original
	report.Finish(&err)
	if !errors.Is(err, writeErr) || !errors.Is(err, original) {
		t.Fatalf("lost test or output error: %v", err)
	}
}
