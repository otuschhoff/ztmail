package mail

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/discovery"
	"github.com/otuschhoff/adbind/ad/observe"
)

func TestDCInventoryHistoryAcrossGroupsAndGenerationOrder(t *testing.T) {
	for _, groups := range [][2]string{{"advertised", "current"}, {"current", "retired"}, {"retired", "advertised"}, {"all", "all"}} {
		for _, reversed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-%s/reversed=%t", groups[0], groups[1], reversed), func(t *testing.T) {
				report := NewTestReport(io.Discard, false)
				report.EnableDebug()
				report.started, report.snapshotAt = fixtureEpoch, fixtureEpoch.Add(time.Second)
				events := []discovery.InventoryEvent{
					historyInventory(groups[0], "192.0.2.10", 2),
					historyInventory(groups[1], "192.0.2.20", 1),
				}
				if reversed {
					slices.Reverse(events)
				}
				before := copyHistoryEvents(t, events)
				for _, event := range events {
					report.Inventory(event)
				}
				for _, protocol := range []string{"ldap", "dns"} {
					port := "389"
					if protocol == "dns" {
						port = "53"
					}
					for i, ip := range []string{"192.0.2.10", "192.0.2.20"} {
						report.Trace(t.Context(), observe.TraceEvent{
							Kind: observe.ExchangeTrace, Phase: observe.TraceCompleted, Protocol: protocol,
							Server: ip + ":" + port, Response: true, Outcome: observe.Success,
							Duration: time.Duration(10+20*i) * time.Millisecond,
						})
					}
					for _, event := range []observe.TraceEvent{
						{Kind: observe.ExchangeTrace, Outcome: observe.Canceled},
						{Kind: observe.ConnectionTrace, Outcome: observe.Success},
					} {
						event.Phase, event.Protocol, event.Server, event.Duration = observe.TraceCompleted, protocol, "192.0.2.10:"+port, time.Hour
						report.Trace(t.Context(), event)
					}
				}
				checkHistoryRows(t, report)
				for range 3 {
					for _, format := range []reportFormat{reportTerminal, reportPlain, reportHTML} {
						checkHistoryText(t, fmt.Sprint(format), report.renderDebug(format))
					}
					data, err := report.jsonSnapshot()
					if err != nil {
						t.Fatal(err)
					}
					checkHistoryJSON(t, data)
				}
				bodies, attachment := diagnosticMIME(t, report)
				for name, body := range bodies {
					checkHistoryText(t, name, body)
				}
				checkHistoryJSON(t, attachment)
				if !reflect.DeepEqual(events, before) || !reflect.DeepEqual(report.inventory, before) {
					t.Fatal("aggregation changed caller input or original generation/health evidence")
				}
			})
		}
	}
}

func TestDCInventoryOwnsEveryNestedSliceAfterReturn(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	event := historyInventory("all", "192.0.2.10", 7)
	expected := copyHistoryEvents(t, []discovery.InventoryEvent{event})
	report.Inventory(event)
	mutateHistoryInput(&event)
	if !reflect.DeepEqual(report.inventory, expected) {
		t.Fatal("retained inventory aliases caller endpoint/address slices or changed metadata")
	}
	report.Trace(t.Context(), observe.TraceEvent{
		Kind: observe.ExchangeTrace, Phase: observe.TraceCompleted, Protocol: "ldap",
		Server: "192.0.2.10:389", Response: true, Duration: 10 * time.Millisecond,
	})
	rows := report.dcObservationTable().rows
	if len(rows) != 1 || rows[0][0] != "dc.corp.example:389" || rows[0][3] != "10.0ms" || rows[0][4] != "1" {
		t.Fatalf("caller mutation changed retained response evidence: %v", rows)
	}
	if !reflect.DeepEqual(report.inventory, expected) {
		t.Fatal("rendering changed raw inventory")
	}
}

func TestDCInventoryRenderingDoesNotMutateStoredAddresses(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	// Deliberately retain spare capacity to expose DNS append aliases even
	// independently of the ingestion copy's allocation strategy.
	addresses := make([]netip.Addr, 1, 4)
	addresses[0] = netip.MustParseAddr("192.0.2.10")
	addresses[:cap(addresses)][1] = netip.MustParseAddr("192.0.2.99")
	other := discovery.Endpoint{FQDN: "dc.corp.example", Port: 88, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.20")}}
	report.inventory = []discovery.InventoryEvent{{Advertised: []discovery.Endpoint{
		{FQDN: "dc.corp.example", Port: 389, Addresses: addresses}, other,
	}}}
	report.Trace(t.Context(), observe.TraceEvent{Kind: observe.ExchangeTrace, Phase: observe.TraceCompleted,
		Protocol: "dns", Server: "dc.corp.example:53", Response: true, Duration: time.Millisecond})
	before := slices.Clone(addresses[:cap(addresses)])
	for range 3 {
		report.dcObservationTable()
	}
	if !slices.Equal(addresses[:cap(addresses)], before) {
		t.Fatal("DNS matching appended into stored inventory backing array")
	}
}

func TestDCAddressHistoryUnionOwnsAndDeduplicates(t *testing.T) {
	a, b := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")
	first, second := []netip.Addr{a, a}, []netip.Addr{b, a, b}
	var endpoint discovery.Endpoint
	appendDCAddresses(&endpoint, first)
	appendDCAddresses(&endpoint, second)
	if !slices.Equal(endpoint.Addresses, []netip.Addr{a, b}) {
		t.Fatalf("address union=%v, want distinct A/B", endpoint.Addresses)
	}
	first[0], second[0] = b, a
	if !slices.Equal(endpoint.Addresses, []netip.Addr{a, b}) {
		t.Fatal("address union aliases its inputs")
	}
	endpoint.Addresses[0] = b
	if first[1] != a || second[1] != a {
		t.Fatal("address union mutation changed an input")
	}
}

func TestDCInventoryConcurrentOwnedIngestionAndRendering(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	report.EnableDebug()
	var observers sync.WaitGroup
	start := make(chan struct{})
	for _, ip := range []string{"192.0.2.10", "192.0.2.20"} {
		observers.Go(func() {
			<-start
			for i := range 20 {
				event := historyInventory("all", ip, uint64(i+1))
				report.Inventory(event)
				// Producers may reuse their callback slices after Inventory returns,
				// while report rendering and other observer calls continue.
				mutateHistoryInput(&event)
				duration := 10 * time.Millisecond
				if ip == "192.0.2.20" {
					duration = 30 * time.Millisecond
				}
				report.Trace(t.Context(), observe.TraceEvent{
					Kind: observe.ExchangeTrace, Phase: observe.TraceCompleted, Protocol: "ldap",
					Server: ip + ":389", Response: true, Duration: duration,
				})
			}
		})
	}
	defer observers.Wait()
	close(start)
	for range 20 {
		bodies, data := diagnosticMIME(t, report)
		var snapshot jsonTestReport
		if err := json.Unmarshal(data, &snapshot); err != nil {
			t.Fatal(err)
		}
		for _, table := range snapshot.Tables {
			if table.ID == "dc_observations" {
				for _, row := range table.Rows {
					if row[0] != "dc.corp.example:389" || row[2] != "Responded" {
						t.Errorf("incoherent owned evidence: %v", row)
					}
					for name, body := range bodies {
						if !strings.Contains(body, row[0]) || !strings.Contains(body, row[3]) {
							t.Errorf("%s disagrees with JSON response snapshot: %v", name, row)
						}
					}
				}
			}
		}
		report.mu.Lock()
		report.renderDebug(reportTerminal)
		report.mu.Unlock()
	}
	observers.Wait()
	rows := report.dcObservationTable().rows
	if len(rows) != 1 || rows[0][0] != "dc.corp.example:389" || rows[0][2] != "Responded" ||
		rows[0][3] != "20.0ms" || rows[0][4] != "40" {
		t.Fatalf("lost or corrupted concurrent response evidence: %v", rows)
	}
}

func historyInventory(group, ip string, generation uint64) discovery.InventoryEvent {
	health := discovery.HealthHealthy
	if generation%2 == 0 {
		health = discovery.HealthUnavailable
	}
	endpoint := discovery.Endpoint{
		FQDN: "dc.corp.example", Port: 389, Role: discovery.RoleLDAP, Priority: 10, Weight: 20, LocalSite: true,
		Addresses: []netip.Addr{netip.MustParseAddr(ip), netip.MustParseAddr(ip)},
		Health: discovery.EndpointHealth{
			Status: health, Reason: fmt.Sprintf("generation %d", generation),
			Generation: generation, Revision: generation + 10, At: fixtureEpoch, NextProbe: fixtureEpoch.Add(time.Hour),
		},
	}
	event := discovery.InventoryEvent{
		Domain: "corp.example", Site: "local", Published: true,
		Scope: observe.Scope{ID: observe.ScopeID(generation)},
		Current: discovery.ServiceInventory{Role: discovery.RoleLDAP, Discovered: true,
			Generation: generation, ProtectionRevision: generation + 10},
	}
	if group == "advertised" || group == "all" {
		event.Advertised = []discovery.Endpoint{endpoint}
		event.Advertised[0].Addresses = slices.Clone(endpoint.Addresses)
	}
	if group == "current" || group == "all" {
		event.Current.Candidates = []discovery.Endpoint{endpoint}
		event.Current.Candidates[0].Addresses = slices.Clone(endpoint.Addresses)
	}
	if group == "retired" || group == "all" {
		event.Retired = []discovery.Endpoint{endpoint}
		event.Retired[0].Addresses = slices.Clone(endpoint.Addresses)
	}
	return event
}

func mutateHistoryInput(event *discovery.InventoryEvent) {
	for _, group := range [][]discovery.Endpoint{event.Advertised, event.Current.Candidates, event.Retired} {
		for i := range group {
			group[i].Addresses[0] = netip.MustParseAddr("203.0.113.99")
			group[i] = discovery.Endpoint{FQDN: "mutated.invalid", Port: 1}
		}
	}
}

func copyHistoryEvents(t *testing.T, events []discovery.InventoryEvent) []discovery.InventoryEvent {
	t.Helper()
	data, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	var result []discovery.InventoryEvent
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func checkHistoryRows(t *testing.T, report *TestReport) {
	t.Helper()
	rows := report.dcObservationTable().rows
	if len(rows) != 2 {
		t.Fatalf("rows=%v, want DNS and LDAP lifetime observations", rows)
	}
	for _, row := range rows {
		if row[2] != "Responded" || row[3] != "20.0ms" || row[4] != "2" {
			t.Errorf("lost historical reply or included canceled/connection-only duration: %v", row)
		}
	}
}

func checkHistoryText(t *testing.T, name, text string) {
	t.Helper()
	for _, want := range []string{"dc.corp.example:389", "dc.corp.example:53", "Responded", "20.0ms"} {
		if !strings.Contains(text, want) {
			t.Errorf("%s missing %s:\n%s", name, want, text)
		}
	}
	for _, absent := range []string{"failed attempts", "generation", "mutated.invalid", "203.0.113.99"} {
		if strings.Contains(text, absent) {
			t.Errorf("%s has unexpected metadata/attempt claim %q", name, absent)
		}
	}
}

func checkHistoryJSON(t *testing.T, data []byte) {
	t.Helper()
	rows := diagnosticJSONTable(t, data, "dc_observations")
	want := [][]string{
		{"dc.corp.example:53", "dns", "Responded", "20.0ms", "2"},
		{"dc.corp.example:389", "ldap", "Responded", "20.0ms", "2"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("JSON lifetime evidence=%v, want %v", rows, want)
	}
}
