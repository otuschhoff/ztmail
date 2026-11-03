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
	for _, key := range []string{"Hostname", "Target relay", "AD domain", "User", "Mail (from)",
		"Cred source", "Authentication method", "SPN", "Transport security", "Authentication", "Total runtime"} {
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
	report.Value("Transport security", "OK (CN=smtp.corp.example; +69 days)")
	report.Step("SMTP AUTH GSSAPI", nil, "accepted")
	var err error
	report.Finish(&err)
	for _, want := range []string{"\x1b[90m.CORP.EXAMPLE\x1b[0m", "\x1b[90m@Corp.Example\x1b[0m",
		"\x1b[1m\x1b[32mOK\x1b[0m (CN=smtp\x1b[90m.corp.example\x1b[0m; +69 days)", "\x1b[90m╭", "Authentication"} {
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
	for _, want := range []string{"DNS", "100.0ms", "200.0ms", "counted once"} {
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
	for _, want := range []string{"dc1.corp.example:389",
		"20.0ms", "Responded",
		"OS-managed / unavailable", "SMTP test step", "not additive"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q:\n%s", want, &output)
		}
		if strings.Contains(output.String(), "unresolved.corp.example:389") || strings.Contains(output.String(), "Not tested") {
			t.Fatalf("untested endpoint rendered:\n%s", &output)
		}
	}
	if strings.Contains(output.String(), "Avg response") && !strings.Contains(output.String(), "20.0ms") {
		t.Fatal("started or elected observations counted as completed response latency")
	}
}

func TestDebugSSPIAndObservedDCDNSLatency(t *testing.T) {
	report := NewTestReport(&bytes.Buffer{}, false)
	report.EnableDebug()
	report.Value("Cred source", "SSPI")
	report.Inventory(discovery.InventoryEvent{Advertised: []discovery.Endpoint{
		{FQDN: "dc1.corp.example", Port: 389, Addresses: []netip.Addr{
			netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")}},
		{FQDN: "dc1.corp.example", Port: 88, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
		{FQDN: "dc2.corp.example", Port: 389, Addresses: []netip.Addr{netip.MustParseAddr("2001:db8::20")}},
	}})
	for _, event := range []observe.TraceEvent{
		{Protocol: "dns", Server: "192.0.2.10:53", Response: true, Duration: 10 * time.Millisecond},
		{Protocol: "dns", Server: "192.0.2.11:53", Response: true, Duration: 30 * time.Millisecond},
		{Protocol: "dns", Server: "[2001:db8::20]:5353", Response: true, Duration: 5 * time.Millisecond},
		{Protocol: "dns", Server: "192.0.2.99:53", Response: true, Duration: time.Hour},
		{Protocol: "dns", Server: "192.0.2.10:53", Outcome: observe.Canceled, Duration: time.Hour},
		{Protocol: "ldap", Server: "192.0.2.10:389", Response: true, Duration: 7 * time.Millisecond},
		{Protocol: "kerberos", Server: "192.0.2.10:88", Response: true, Duration: 9 * time.Millisecond},
	} {
		event.Kind, event.Phase = observe.ExchangeTrace, observe.TraceCompleted
		report.Trace(context.Background(), event)
	}
	report.Trace(context.Background(), observe.TraceEvent{Kind: observe.ConnectionTrace, Phase: observe.TraceCompleted,
		Protocol: "dns", Server: "192.0.2.10:53", Outcome: observe.Success, Duration: time.Hour})
	report.Trace(context.Background(), observe.TraceEvent{Kind: observe.ExchangeTrace, Phase: observe.TraceStarted,
		Protocol: "dns", Server: "192.0.2.10:53", Response: true, Duration: time.Hour})
	plain := report.renderDebug(reportPlain)
	if strings.Contains(plain, "Protocol: kerberos") || strings.Contains(plain, "192.0.2.99") ||
		strings.Count(plain, "Protocol: dns") != 2 {
		t.Fatalf("incorrect SSPI/DNS inventory:\n%s", plain)
	}
	for _, want := range []string{
		"dc1.corp.example:53\nProtocol: dns", "Avg response: 20.0ms\nReplies: 2",
		"dc2.corp.example:5353\nProtocol: dns", "Avg response: 5.0ms\nReplies: 1",
		"Avg response: 7.0ms\nReplies: 1",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("missing %q:\n%s", want, plain)
		}
	}
	for _, format := range []reportFormat{reportTerminal, reportHTML} {
		result := report.renderDebug(format)
		if strings.Contains(result, "kerberos") || !strings.Contains(result, "20.0ms") {
			t.Errorf("incorrect SSPI format %v:\n%s", format, result)
		}
	}
	report.Value("Cred source", "keytab")
	if !strings.Contains(report.renderDebug(reportPlain), "Protocol: kerberos") {
		t.Fatal("Kerberos rows hidden for keytab credentials")
	}
}

func TestDCInventorySortedByHostThenMethod(t *testing.T) {
	report := NewTestReport(&bytes.Buffer{}, false)
	report.EnableDebug()
	report.Inventory(discovery.InventoryEvent{Advertised: []discovery.Endpoint{
		{FQDN: "zulu.corp.example", Port: 389, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.20")}},
		{FQDN: "Alpha.corp.example", Port: 88, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
		{FQDN: "Alpha.corp.example", Port: 389, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
	}})
	report.Trace(context.Background(), observe.TraceEvent{Kind: observe.ExchangeTrace, Phase: observe.TraceCompleted,
		Protocol: "dns", Server: "192.0.2.10:53", Response: true, Duration: time.Millisecond})
	for _, event := range []observe.TraceEvent{
		{Protocol: "kerberos", Server: "192.0.2.10:88"},
		{Protocol: "ldap", Server: "192.0.2.10:389"},
		{Protocol: "ldap", Server: "192.0.2.20:389"},
	} {
		event.Kind, event.Phase, event.Response = observe.ExchangeTrace, observe.TraceCompleted, true
		report.Trace(context.Background(), event)
	}
	for _, format := range []reportFormat{reportPlain, reportTerminal, reportHTML} {
		result := report.renderDebug(format)
		previous := -1
		for _, address := range []string{"Alpha.corp.example:53", "Alpha.corp.example:88",
			"Alpha.corp.example:389", "zulu.corp.example:389"} {
			index := strings.Index(result, address)
			if index < 0 || index <= previous {
				t.Fatalf("format %v: wrong DC order at %q:\n%s", format, address, result)
			}
			previous = index
		}
	}
	plain := report.renderDebug(reportPlain)
	kerberos := strings.Index(plain, "Protocol: kerberos")
	ldap := strings.Index(plain, "Protocol: ldap")
	if kerberos < 0 || ldap < kerberos {
		t.Fatalf("protocols not sorted before port:\n%s", plain)
	}
}

func TestDCObservationMissingResponses(t *testing.T) {
	endpoint := discovery.Endpoint{FQDN: "dc.corp.example", Port: 389,
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
	for _, tc := range []struct {
		kind    observe.TraceKind
		outcome observe.Outcome
		want    string
	}{
		{observe.ExchangeTrace, observe.Canceled, ""},
		{observe.ConnectionTrace, observe.Canceled, ""},
		{observe.ExchangeTrace, observe.Failed, "Failed observed attempts"},
		{observe.ConnectionTrace, observe.Success, "Connected; no complete reply"},
	} {
		report := NewTestReport(&bytes.Buffer{}, false)
		report.Trace(context.Background(), observe.TraceEvent{Kind: tc.kind, Phase: observe.TraceCompleted,
			Protocol: "ldap", Server: endpoint.Address(), Outcome: tc.outcome, Duration: time.Second})
		row := report.dcObservationRow(endpoint.Address(), "ldap", endpoint)
		if tc.want == "" {
			if row != nil {
				t.Fatalf("canceled-only row must be omitted: %v", row)
			}
			continue
		}
		if row[2] != tc.want || row[3] != "-" || row[4] != "-" {
			t.Fatalf("incorrect unavailable response metrics: %v", row)
		}
	}
}
