package mail

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/discovery"
	"github.com/otuschhoff/adbind/ad/observe"
)

func TestDCObservationsOnlyShowApplicableObservedServices(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	report.EnableDebug()
	report.Inventory(discovery.InventoryEvent{Advertised: []discovery.Endpoint{
		{FQDN: "dc.corp.example", Port: 88},
		{FQDN: "dc.corp.example", Port: 1389},
		{FQDN: "canceled.corp.example", Port: 88},
		{FQDN: "untested.corp.example", Port: 389},
		{FQDN: "failed.corp.example", Port: 389},
		{FQDN: "connected.corp.example", Port: 389},
	}})
	for _, event := range []observe.TraceEvent{
		{Kind: observe.ExchangeTrace, Protocol: "kerberos", Server: "dc.corp.example:88", Response: true},
		{Kind: observe.ExchangeTrace, Protocol: "ldap", Server: "dc.corp.example:1389", Response: true},
		{Kind: observe.ExchangeTrace, Protocol: "kerberos", Server: "canceled.corp.example:88", Outcome: observe.Canceled},
		{Kind: observe.ExchangeTrace, Protocol: "ldap", Server: "failed.corp.example:389", Outcome: observe.Failed},
		{Kind: observe.ConnectionTrace, Protocol: "ldap", Server: "connected.corp.example:389", Outcome: observe.Success},
		{Kind: observe.ExchangeTrace, Protocol: "ldap", Server: "connected.corp.example:389", Outcome: observe.Canceled},
	} {
		event.Phase, event.Duration = observe.TraceCompleted, time.Millisecond
		report.Trace(context.Background(), event)
	}
	plain := report.renderDebug(reportPlain)
	for _, want := range []string{
		"dc.corp.example:88\nProtocol: kerberos", "dc.corp.example:1389\nProtocol: ldap",
		"Failed observed attempts", "Connected; no complete reply",
	} {
		if !strings.Contains(plain, want) {
			t.Errorf("missing %q:\n%s", want, plain)
		}
	}
	for _, unwanted := range []string{"dc.corp.example:88\nProtocol: ldap", "dc.corp.example:1389\nProtocol: kerberos"} {
		if strings.Contains(plain, unwanted) {
			t.Errorf("non-applicable service shown: %q", unwanted)
		}
	}
	for _, format := range []reportFormat{reportTerminal, reportPlain, reportHTML} {
		result := report.renderDebug(format)
		for _, unwanted := range []string{"canceled.corp.example", "untested.corp.example", "Not tested",
			"Canceled; reachability unknown", "Responded (not authentication proof)"} {
			if strings.Contains(result, unwanted) {
				t.Errorf("format %v includes %q:\n%s", format, unwanted, result)
			}
		}
	}
}

func TestEmptyDCObservations(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	endpoint := discovery.Endpoint{FQDN: "dc.corp.example", Port: 88}
	report.Inventory(discovery.InventoryEvent{Advertised: []discovery.Endpoint{endpoint}})
	report.Trace(context.Background(), observe.TraceEvent{Kind: observe.ExchangeTrace, Phase: observe.TraceCompleted,
		Protocol: "kerberos", Server: endpoint.Address(), Outcome: observe.Canceled})
	if row := report.dcObservationRow(endpoint.Address(), "ldap", endpoint); row != nil {
		t.Fatalf("untested row must be omitted: %v", row)
	}
	for _, format := range []reportFormat{reportTerminal, reportPlain, reportHTML} {
		result := report.renderDebug(format)
		if !strings.Contains(result, "No completed DC responses, failures or connections observed.") ||
			strings.Contains(result, "dc.corp.example") {
			t.Fatalf("incorrect empty observations for %v:\n%s", format, result)
		}
	}
}
