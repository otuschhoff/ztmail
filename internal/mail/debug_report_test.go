package mail

import (
	"bytes"
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/discovery"
	"github.com/otuschhoff/adbind/ad/observe"
)

func TestGSSAPISummary(t *testing.T) {
	var output bytes.Buffer
	report := NewTestReport(&output, false)
	for key, value := range map[string]string{
		"Hostname": "worker.corp.example", "Target relay": "relay.corp.example:25",
		"AD domain": "corp.example", "User": "user@CORP.EXAMPLE",
		"Mail (from)": "sender@corp.example", "Cred source": "sspi", "SPN": "smtp/relay.corp.example",
	} {
		report.Value(key, value)
	}
	report.Step("SMTP STARTTLS", nil, "verified TLS")
	report.Step("SMTP AUTH GSSAPI", nil, "accepted")
	var err error
	report.Finish(&err)
	if err != nil {
		t.Fatal(err)
	}
	plain := report.renderFormat(reportPlain)
	previous := -1
	for _, key := range []string{"Hostname", "Target relay", "AD domain", "Mail (from)", "Authentication method", "User",
		"Cred source", "SPN", "Transport security", "Authentication", "Total runtime"} {
		if strings.Count(plain, "\n"+key+":") != 1 && !strings.HasPrefix(plain, key+":") {
			t.Errorf("missing/duplicate key %q:\n%s", key, &output)
		}
		index := strings.Index(plain, key+":")
		if index <= previous {
			t.Errorf("incorrect key order at %q:\n%s", key, plain)
		}
		previous = index
	}
	for _, want := range []string{"Authentication method: GSSAPI", "SPN: smtp/relay.corp.example"} {
		if !strings.Contains(plain, want) {
			t.Errorf("missing %q:\n%s", want, plain)
		}
	}
	for _, unwanted := range []string{"DC inventory", "Step timings", "[OK] Test", "CHECK"} {
		if strings.Contains(output.String(), unwanted) {
			t.Errorf("unexpected detail %q:\n%s", unwanted, &output)
		}
	}
}

func TestSummaryHidesGSSAPIFieldsForOtherMethods(t *testing.T) {
	report := NewTestReport(&bytes.Buffer{}, false)
	report.Value("Authentication method", "mTLS")
	report.Value("User", "user@corp.example")
	report.Value("Cred source", "keytab")
	report.Value("SPN", "smtp/relay.corp.example")
	for _, format := range []reportFormat{reportTerminal, reportPlain, reportHTML} {
		result := report.renderFormat(format)
		if !strings.Contains(result, "mTLS") || !strings.Contains(result, "Mail (from)") {
			t.Errorf("missing common fields:\n%s", result)
		}
		for _, unwanted := range []string{"User", "Cred source", "SPN", "user@corp.example", "keytab", "smtp/relay.corp.example"} {
			if strings.Contains(result, unwanted) {
				t.Errorf("non-GSSAPI report contains %q:\n%s", unwanted, result)
			}
		}
	}
}

func TestDomainDimmingAndConciseStatuses(t *testing.T) {
	var output bytes.Buffer
	report := NewTestReport(&output, false)
	report.color = true
	report.Value("AD domain", "corp.example")
	report.Value("Hostname", "worker.CORP.EXAMPLE")
	report.Value("User", "user@Corp.Example")
	report.Value("Transport security", "OK (CN=smtp.corp.example; 69 days left)")
	report.Step("SMTP AUTH GSSAPI", nil, "accepted")
	var err error
	report.Finish(&err)
	for _, want := range []string{"\x1b[90m.CORP.EXAMPLE\x1b[0m", "\x1b[90m@Corp.Example\x1b[0m",
		"\x1b[1m\x1b[32mOK\x1b[0m (CN=smtp\x1b[90m.corp.example\x1b[0m; 69 days left)", "\x1b[90m╭", "Authentication"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q:\n%q", want, output.String())
		}
	}
	for _, unwanted := range []string{"│ KEY", "│ VALUE", "Authentication result", "GSSAPI accepted"} {
		if strings.Contains(output.String(), unwanted) {
			t.Errorf("unexpected %q", unwanted)
		}
	}
	if got := formatDomain("relay.corp.example.attacker.test", reportTerminal, true, "corp.example"); strings.Contains(got, "\x1b[90m") {
		t.Fatal("domain prefix in external hostname dimmed")
	}
}

func TestRuntimeBreakdownDoesNotDoubleCount(t *testing.T) {
	report := NewTestReport(&bytes.Buffer{}, false)
	report.started = time.Now().Add(-time.Second)
	end := report.started.Add(500 * time.Millisecond)
	report.traces = []observe.TraceEvent{
		{Protocol: "dns", Duration: 100 * time.Millisecond},
		{Operation: "credential_acquire", Duration: 300 * time.Millisecond},
		{Operation: "SMTP GSSAPI authentication", Duration: 50 * time.Millisecond},
	}
	report.traceEnds = []time.Time{end, end, end}
	text := report.runtimeBreakdown()
	for _, want := range []string{"DNS", "100ms", "200ms", "SMTP auth", "counted once"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q:\n%s", want, text)
		}
	}
}

func TestDebugObservedInventoryAndTimings(t *testing.T) {
	var output bytes.Buffer
	report := NewTestReport(&output, true)
	report.EnableDebug()
	report.Inventory(discovery.InventoryEvent{Advertised: []discovery.Endpoint{
		{FQDN: "dc1.corp.example", Port: 389, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
		{FQDN: "unresolved.corp.example", Port: 389},
	}})
	var wg sync.WaitGroup
	for _, duration := range []time.Duration{10 * time.Millisecond, 30 * time.Millisecond} {
		wg.Go(func() {
			report.Trace(context.Background(), observe.TraceEvent{Kind: observe.ExchangeTrace,
				Phase: observe.TraceCompleted, Protocol: "ldap", Server: "192.0.2.10:389",
				Response: true, Outcome: observe.Success, Duration: duration, Operation: "search"})
		})
	}
	wg.Wait()
	report.Trace(context.Background(), observe.TraceEvent{Kind: observe.ExchangeTrace,
		Phase: observe.TraceStarted, Protocol: "ldap", Server: "192.0.2.10:389",
		Response: true, Duration: time.Hour})
	report.Exchange(context.Background(), observe.ExchangeEvent{Protocol: "ldap",
		Server: "192.0.2.10:389", Outcome: observe.Success, Duration: time.Hour})
	done := report.Measure("SMTP test step")
	done()
	var err error
	report.Finish(&err)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"dc1.corp.example:389", "unresolved.corp.example:389",
		"Not tested", "20ms", "Responded (not authentication proof)",
		"OS-managed / unavailable", "SMTP test step", "not additive"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q:\n%s", want, &output)
		}
	}
	if strings.Contains(output.String(), "Avg response") && !strings.Contains(output.String(), "20ms") {
		t.Fatal("started or elected observations counted as completed response latency")
	}
}
