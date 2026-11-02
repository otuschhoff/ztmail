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

func TestNineKeySummary(t *testing.T) {
	var output bytes.Buffer
	report := NewTestReport(&output, false)
	for key, value := range map[string]string{
		"Hostname": "worker.corp.example", "Target relay": "relay.corp.example:25",
		"AD domain": "corp.example", "User": "user@CORP.EXAMPLE",
		"Mail (from)": "sender@corp.example", "Cred source": "sspi",
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
	for _, key := range []string{"Hostname", "Target relay", "AD domain", "User", "Mail (from)",
		"Cred source", "Transport security", "Authentication result", "Total runtime"} {
		if strings.Count(output.String(), key) != 1 {
			t.Errorf("missing/duplicate key %q:\n%s", key, &output)
		}
	}
	for _, unwanted := range []string{"DC inventory", "Step timings", "[OK] Test", "CHECK"} {
		if strings.Contains(output.String(), unwanted) {
			t.Errorf("unexpected detail %q:\n%s", unwanted, &output)
		}
	}
}

func TestDebugObservedInventoryAndTimings(t *testing.T) {
	var output bytes.Buffer
	report := NewTestReport(&output, false)
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
	if strings.Contains(output.String(), "1h") {
		t.Fatal("started or elected observations counted as completed response latency")
	}
}
