package mail

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/observe"
)

func TestRuntimeCategories(t *testing.T) {
	for _, test := range []struct {
		operation string
		protocol  string
		want      int
	}{
		{"credential_acquire", "", runtimeKerberos},
		{"principal_selection", "", runtimeKerberos},
		{"service_ticket", "", runtimeKerberos},
		{"lookup", "dns", runtimeDNS},
		{"search", "ldap", runtimeLDAP},
		{"SMTP STARTTLS", "", runtimeSMTPHandshake},
		{"SMTP GSSAPI authentication", "", runtimeSMTPAuth},
		{"SMTP QUIT", "smtp", runtimeSMTPQuit},
		{"GSSAPI cleanup", "", runtimeCleanup},
		{"SMTP connection cleanup", "smtp", runtimeCleanup},
		{"AD credential cleanup", "", runtimeCleanup},
		{"Host/domain discovery", "", runtimeHostDiscovery},
		{"Local user lookup", "", runtimeUserLookup},
		{"Credential prompt", "", runtimeCredentialPrompt},
		{"Report preparation", "", runtimeReportPreparation},
		{"Report output", "", runtimeReportPreparation},
		{"AD identity and canonical mail", "", runtimeADSetup},
		{"AD client setup", "", runtimeADSetup},
		{"AD source configuration", "", runtimeADSetup},
		{"Keytab inspection", "", runtimeKerberos},
		{"Keytab principal selection", "", runtimeKerberos},
		{"password prompt", "", runtimeOther},
	} {
		t.Run(test.operation, func(t *testing.T) {
			got := runtimeCategory(observe.TraceEvent{Operation: test.operation, Protocol: test.protocol})
			if got != test.want {
				t.Fatalf("got category %d, want %d", got, test.want)
			}
		})
	}
}

func TestRuntimeBreakdownSeparatesQuitAndCleanup(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	report.started = time.Now().Add(-time.Second)
	end := report.started
	for i, operation := range []string{"DNS lookup", "credential_acquire", "LDAP search", "SMTP EHLO",
		"SMTP GSSAPI authentication", "SMTP QUIT", "AD credential cleanup"} {
		duration := time.Duration(i+1) * 10 * time.Millisecond
		end = end.Add(duration)
		report.traces = append(report.traces, observe.TraceEvent{Operation: operation, Duration: duration})
		report.traceEnds = append(report.traceEnds, end)
	}
	// A nested close during QUIT must not count the same wall time twice.
	report.traces = append(report.traces, observe.TraceEvent{Operation: "SMTP connection cleanup", Duration: 20 * time.Millisecond})
	report.traceEnds = append(report.traceEnds, end.Add(-70*time.Millisecond))
	result := report.runtimeBreakdownFormat(reportPlain)
	for _, want := range []string{
		"DNS: 10.0ms", "Kerberos credentials / tickets: 20.0ms", "LDAP: 30.0ms",
		"SMTP handshake: 40.0ms", "SMTP auth: 50.0ms", "SMTP QUIT: 60.0ms",
		"Cleanup: 70.0ms", "Other / untracked:",
	} {
		if !strings.Contains(result, want) {
			t.Errorf("missing %q:\n%s", want, result)
		}
	}
	if strings.Contains(result, "Other / cleanup") {
		t.Errorf("old combined category remains:\n%s", result)
	}
}

func TestRuntimeBreakdownAttributesNestedADWork(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	report.started = time.Now().Add(-time.Second)
	for _, step := range []struct {
		operation string
		start     time.Duration
		duration  time.Duration
	}{
		{"Host/domain discovery", 0, 100 * time.Millisecond},
		{"AD identity and canonical mail", 100 * time.Millisecond, 800 * time.Millisecond},
		{"Local user lookup", 100 * time.Millisecond, 100 * time.Millisecond},
		{"Credential prompt", 200 * time.Millisecond, 300 * time.Millisecond},
		{"credential_acquire", 500 * time.Millisecond, 200 * time.Millisecond},
		{"LDAP search", 700 * time.Millisecond, 50 * time.Millisecond},
		{"Report output", 750 * time.Millisecond, 50 * time.Millisecond},
	} {
		report.traces = append(report.traces, observe.TraceEvent{Operation: step.operation, Duration: step.duration})
		report.traceEnds = append(report.traceEnds, report.started.Add(step.start+step.duration))
	}
	result := report.runtimeBreakdownFormat(reportPlain)
	if !strings.HasPrefix(result, "Runtime breakdown\nCredential prompting: 300.0ms\nAD setup / orchestration: 100.0ms\n") {
		t.Errorf("credential prompting and AD setup/orchestration are not first:\n%s", result)
	}
	for _, want := range []string{
		"Host/domain discovery: 100.0ms", "Local user lookup: 100.0ms", "Credential prompting: 300.0ms",
		"Kerberos credentials / tickets: 200.0ms", "LDAP: 50.0ms",
		"Report preparation / output: 50.0ms", "AD setup / orchestration: 100.0ms",
	} {
		if !strings.Contains(result, want) {
			t.Errorf("missing %q:\n%s", want, result)
		}
	}
	for _, format := range []reportFormat{reportTerminal, reportHTML} {
		result := report.runtimeBreakdownFormat(format)
		for _, label := range []string{"Host/domain discovery", "Local user lookup", "Credential prompting",
			"Report preparation / output", "AD setup / orchestration", "Other / untracked"} {
			if !strings.Contains(result, label) {
				t.Errorf("format=%v: missing %q:\n%s", format, label, result)
			}
		}
		if strings.Index(result, "AD setup / orchestration") > strings.Index(result, "Kerberos credentials / tickets") {
			t.Errorf("format=%v: AD setup/orchestration is not first:\n%s", format, result)
		}
		if strings.Index(result, "Credential prompting") > strings.Index(result, "AD setup / orchestration") {
			t.Errorf("format=%v: credential prompting is not first:\n%s", format, result)
		}
	}
}

func TestRuntimeBreakdownHidesRowsBelowThreshold(t *testing.T) {
	for _, test := range []struct {
		duration time.Duration
		want     string
	}{
		{0, ""},
		{time.Nanosecond, ""},
		{50 * time.Microsecond, ""},
		{100*time.Microsecond - time.Nanosecond, ""},
		{100 * time.Microsecond, "0.1ms"},
		{100*time.Microsecond + time.Nanosecond, "0.1ms"},
		{time.Millisecond, "1.0ms"},
	} {
		t.Run(test.duration.String(), func(t *testing.T) {
			report := NewTestReport(io.Discard, false)
			report.started = time.Now().Add(-time.Second)
			report.traces = []observe.TraceEvent{{Protocol: "dns", Duration: test.duration}}
			report.traceEnds = []time.Time{report.started.Add(test.duration)}
			for _, format := range []reportFormat{reportPlain, reportTerminal, reportHTML} {
				result := report.runtimeBreakdownFormat(format)
				if strings.Contains(result, "SMTP auth") {
					t.Errorf("format=%v: zero-duration row remains:\n%s", format, result)
				}
				if test.want != "" && (!strings.Contains(result, "DNS") || !strings.Contains(result, test.want)) {
					t.Errorf("format=%v: missing visible duration %q:\n%s", format, test.want, result)
				}
				// The explanatory note mentions DNS even when its row is hidden.
				rows, _, _ := strings.Cut(result, "Observed wall-time estimate")
				if test.want == "" && strings.Contains(rows, "DNS") {
					t.Errorf("format=%v: sub-threshold DNS row remains:\n%s", format, result)
				}
			}
		})
	}
}

func TestExecutionRuntimeExcludesPromptInterval(t *testing.T) {
	for _, debug := range []bool{false, true} {
		report := NewTestReport(io.Discard, false)
		if debug {
			report.EnableDebug()
		}
		done := report.Measure("Credential prompt")
		report.MarkPasswordPrompted()
		time.Sleep(time.Millisecond)
		done()
		if !report.passwordPrompted || report.promptDuration < time.Millisecond {
			t.Fatalf("debug=%v: prompt duration was not captured: %s", debug, report.promptDuration)
		}
		if (len(report.traces) > 0) != debug {
			t.Fatalf("debug=%v: trace collection changed", debug)
		}
		report.snapshotAt = time.Now()
		total := report.snapshotAt.Sub(report.started)
		rows := report.summaryTable().rows
		if rows[len(rows)-2][0] != "Total runtime" || rows[len(rows)-1][0] != "Execution runtime" ||
			rows[len(rows)-1][1] != formatDuration(total-report.promptDuration) {
			t.Fatalf("debug=%v: incorrect execution runtime/order: %v", debug, rows)
		}
	}
}

func TestExecutionRuntimeSummary(t *testing.T) {
	for _, prompted := range []bool{false, true} {
		report := NewTestReport(io.Discard, false)
		report.snapshotAt = time.Now()
		report.started = report.snapshotAt.Add(-20 * time.Second)
		report.passwordPrompted = prompted
		report.promptDuration = 12 * time.Second
		report.Value("Cred source", "password")
		for _, format := range []reportFormat{reportTerminal, reportHTML, reportPlain} {
			result := report.renderFormat(format)
			if strings.Contains(result, "Execution runtime") != prompted {
				t.Fatalf("prompted=%v format=%v: wrong execution-runtime visibility:\n%s", prompted, format, result)
			}
			if prompted && (!strings.Contains(result, "8.0s") ||
				strings.Index(result, "Execution runtime") < strings.Index(result, "Total runtime")) {
				t.Fatalf("prompted=%v format=%v: wrong execution-runtime value/order:\n%s", prompted, format, result)
			}
		}
	}
}

func TestReportOutputMeasurement(t *testing.T) {
	report := NewTestReport(io.Discard, true)
	report.EnableDebug()
	report.Line("INFO", "Synthetic event", "details")
	assertMeasuredOperation(t, report, "Report output", 1)
}

func assertMeasuredOperation(t *testing.T, report *TestReport, operation string, want int) {
	t.Helper()
	count := 0
	for _, event := range report.traces {
		if event.Operation == operation && event.Phase == observe.TraceCompleted {
			count++
			if event.Duration <= 0 {
				t.Errorf("%s has no elapsed time", operation)
			}
		}
	}
	if count != want {
		t.Errorf("%s: got %d completed measurements, want %d", operation, count, want)
	}
}
