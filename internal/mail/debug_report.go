package mail

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/otuschhoff/adbind/ad/discovery"
	"github.com/otuschhoff/adbind/ad/observe"
)

func (r *TestReport) Value(key, value string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.values[key] = value
}

func (r *TestReport) EnableDebug() {
	if r != nil {
		r.debug = true
	}
}

func (r *TestReport) Trace(_ context.Context, event observe.TraceEvent) {
	if event.Phase != observe.TraceCompleted {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.traces = append(r.traces, event)
}

func (r *TestReport) Inventory(event discovery.InventoryEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inventory = append(r.inventory, event)
}

func (r *TestReport) Measure(step string) func() {
	started := time.Now()
	return func() {
		if r == nil || !r.debug {
			return
		}
		r.Trace(context.Background(), observe.TraceEvent{Kind: observe.OperationTrace,
			Phase: observe.TraceCompleted, Operation: step, Duration: time.Since(started)})
	}
}

func (r *TestReport) renderDebug() string {
	dcs := table.NewWriter()
	dcs.SetStyle(table.StyleRounded)
	dcs.AppendHeader(table.Row{"Discovered DC / service", "Protocol", "Observed reachability", "Avg response", "Replies"})
	seen := make(map[string]discovery.Endpoint)
	for _, event := range r.inventory {
		for _, group := range [][]discovery.Endpoint{event.Advertised, event.Current.Candidates, event.Retired} {
			for _, endpoint := range group {
				key := endpoint.Address()
				if previous, ok := seen[key]; !ok || len(endpoint.Addresses) > 0 || len(previous.Addresses) == 0 {
					seen[key] = endpoint
				}
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		endpoint := seen[key]
		for _, protocol := range []string{"ldap", "kerberos"} {
			var total time.Duration
			replies, failed, canceled, connected, connectionFailures := 0, 0, 0, 0, 0
			for _, event := range r.traces {
				if (event.Kind != observe.ExchangeTrace && event.Kind != observe.ConnectionTrace) || event.Protocol != protocol {
					continue
				}
				matches := strings.EqualFold(event.Server, key)
				host, port, _ := net.SplitHostPort(event.Server)
				for _, address := range endpoint.Addresses {
					if host == address.String() && port == fmt.Sprint(endpoint.Port) {
						matches = true
					}
				}
				if !matches {
					continue
				}
				if event.Kind == observe.ConnectionTrace {
					if event.Outcome == observe.Success {
						connected++
					} else if event.Outcome == observe.Canceled {
						canceled++
					} else {
						connectionFailures++
					}
					continue
				}
				if event.Response {
					replies++
					total += event.Duration
				} else if event.Outcome == observe.Canceled {
					canceled++
				} else {
					failed++
				}
			}
			status, avg := "Not tested", "-"
			if replies > 0 {
				status = "Responded (not authentication proof)"
				avg = (total / time.Duration(replies)).Round(time.Microsecond).String()
			} else if failed > 0 || connectionFailures > 0 {
				status = "Failed observed attempts"
			} else if canceled > 0 {
				status = "Canceled; reachability unknown"
			} else if connected > 0 {
				status = "Connected; no complete reply"
			}
			if replies > 0 && failed > 0 {
				status += fmt.Sprintf("; %d failed attempts", failed)
			}
			dcs.AppendRow(table.Row{key, protocol, status, avg, replies})
		}
	}
	if len(keys) == 0 {
		dcs.AppendRow(table.Row{"No DC advertisements observed", "-", "Not tested", "-", 0})
	}
	timings := table.NewWriter()
	timings.SetStyle(table.StyleRounded)
	timings.AppendHeader(table.Row{"Step", "Kind", "Scope / parent", "Duration", "Outcome"})
	for _, event := range r.traces {
		timings.AppendRow(table.Row{event.Operation, event.Kind, fmt.Sprintf("%d / %d", event.ID, event.ParentID),
			event.Duration.Round(time.Microsecond), event.Outcome})
	}
	return "DC inventory (advertised during this test; includes historical/unresolved entries)\n" + dcs.Render() +
		"\nSSPI KDC endpoints/wire timing: OS-managed / unavailable. DNS resolver traffic is not DC reachability.\n" +
		"Step timings (nested/concurrent durations overlap; not additive)\n" + timings.Render()
}
