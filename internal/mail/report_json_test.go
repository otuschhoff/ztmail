package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	netmail "net/mail"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/discovery"
	"github.com/otuschhoff/adbind/ad/observe"
)

func TestTestmailJSONTablesSnapshot(t *testing.T) {
	for _, mode := range []struct {
		name           string
		debug, verbose bool
	}{
		{"normal", false, false},
		{"verbose", false, true},
		{"debug", true, false},
		{"debug-verbose", true, true},
	} {
		t.Run(mode.name, func(t *testing.T) {
			report := NewTestReport(io.Discard, mode.verbose)
			report.started = time.Now().Add(-2 * time.Second)
			if mode.debug {
				report.EnableDebug()
			}
			user := `Jörg <&> "user"@corp.example`
			path := `/tmp/Jörg<&>.ccache`
			report.Value("User", user)
			report.Value("Cred source", "ccache")
			report.Value("Cred source path", path)
			report.Value("Authentication", "OK")
			report.passwordPrompted = true
			report.promptDuration = time.Second
			report.Value("Unreported internal value", "must-not-be-attached")
			report.Line("WARN", "Synthetic check", user)
			report.TLS(strongTLSState())
			report.KerberosTicket(testTicketMetadata(time.Now()))
			report.Inventory(discovery.InventoryEvent{Advertised: []discovery.Endpoint{
				{FQDN: "dc.corp.example", Port: 389, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}},
			}})
			report.Trace(context.Background(), observe.TraceEvent{
				Kind: observe.ExchangeTrace, Phase: observe.TraceCompleted, Protocol: "ldap",
				Server: "192.0.2.10:389", Response: true, Outcome: observe.Success, Duration: 20 * time.Millisecond,
			})
			traceCount := len(report.traces)
			before := time.Now()
			data, err := report.TestMessage("self@corp.example", []string{"recipient@corp.example"})
			after := time.Now()
			if err != nil {
				t.Fatal(err)
			}
			message, err := netmail.ReadMessage(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			bodies, jsonData := testmailContents(t, message)
			var snapshot jsonTestReport
			if err := json.Unmarshal(jsonData, &snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot.SchemaVersion != 1 || snapshot.SnapshotPhase != "after_smtp_authentication_before_data" ||
				snapshot.SnapshotAt.Before(before) || snapshot.SnapshotAt.After(after) {
				t.Fatalf("incorrect snapshot metadata: %+v", snapshot)
			}
			wantIDs := []string{"summary", "issues"}
			if mode.debug {
				wantIDs = append(wantIDs, "runtime", "dc_observations")
				if mode.verbose {
					wantIDs = append(wantIDs, "step_timings")
				}
				wantIDs = append(wantIDs, "tls", "crypto", "validity")
			}
			var ids []string
			for _, item := range snapshot.Tables {
				ids = append(ids, item.ID)
				if item.Title == "" || len(item.Columns) == 0 {
					t.Fatalf("table lacks title or columns: %+v", item)
				}
				for _, row := range item.Rows {
					if len(row) != len(item.Columns) {
						t.Fatalf("row does not match columns: %+v", item)
					}
				}
				switch item.ID {
				case "summary":
					if len(item.Rows) < 2 || item.Rows[len(item.Rows)-2][0] != "Total runtime" ||
						item.Rows[len(item.Rows)-1][0] != "Execution runtime" {
						t.Fatalf("JSON summary lost the prompted execution runtime or its order: %v", item.Rows)
					}
					for _, row := range item.Rows {
						if !strings.Contains(bodies["text/plain"], row[0]+": "+row[1]) {
							t.Errorf("attachment summary differs from plain text: %v", row)
						}
						if row[0] == "User" && row[1] != user {
							t.Errorf("raw Unicode/user value not preserved: %v", row)
						}
						if row[0] == "Cred source" && row[1] != "ccache ("+path+")" {
							t.Errorf("credential path not preserved: %v", row)
						}
						if row[0] == "Total runtime" && row[1] != formatDuration(snapshot.SnapshotAt.Sub(report.started)) {
							t.Errorf("runtime does not use snapshot time: %v", row)
						}
						if row[0] == "Execution runtime" && row[1] != formatDuration(snapshot.SnapshotAt.Sub(report.started)-report.promptDuration) {
							t.Errorf("execution runtime did not exclude prompting in the JSON snapshot: %v", row)
						}
					}
				case "issues":
					if !reflect.DeepEqual(item.Rows, [][]string{{"[WARN] Synthetic check", user}}) {
						t.Errorf("incorrect issue content: %v", item.Rows)
					}
				case "runtime":
					for _, row := range item.Rows {
						if !strings.Contains(bodies["text/plain"], row[0]+": "+row[1]) {
							t.Errorf("attachment runtime differs from plain text: %v", row)
						}
					}
				case "dc_observations":
					want := [][]string{{"dc.corp.example:389", "ldap", "Responded", "20.0ms", "1"}}
					if !reflect.DeepEqual(item.Rows, want) {
						t.Errorf("incorrect DC content: got %v, want %v", item.Rows, want)
					}
				case "step_timings":
					if len(item.Rows) != traceCount {
						t.Errorf("step timings not captured before report generation: got %d, want %d", len(item.Rows), traceCount)
					}
				case "tls":
					for i, row := range report.tlsDetails {
						for j, cell := range row {
							if item.Rows[i][j] != cell {
								t.Errorf("TLS cell differs from source: %v", item.Rows[i])
							}
						}
					}
				case "crypto":
					for i, row := range report.cryptoTable().rows {
						for j, cell := range row {
							if item.Rows[i][j] != cell {
								t.Errorf("crypto cell differs from source: %v", item.Rows[i])
							}
						}
					}
				case "validity":
					snapshotReport := &TestReport{snapshotAt: snapshot.SnapshotAt, tlsValidity: report.tlsValidity, ticketMetadata: report.ticketMetadata}
					for i, row := range snapshotReport.validityTable().rows {
						for j, cell := range row {
							if item.Rows[i][j] != cell {
								t.Errorf("validity cell differs from source: %v", item.Rows[i])
							}
						}
					}
				}
			}
			if !reflect.DeepEqual(ids, wantIDs) {
				t.Errorf("table selection/order: got %v, want %v", ids, wantIDs)
			}
			if bytes.Contains(jsonData, []byte("must-not-be-attached")) || bytes.Contains(jsonData, []byte{0x1b}) {
				t.Fatal("unreported data or terminal styling leaked into JSON")
			}
		})
	}
}

func TestTestmailOmitsDCRowsWithoutResponseLatency(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	report.EnableDebug()
	report.Inventory(discovery.InventoryEvent{Advertised: []discovery.Endpoint{
		{FQDN: "connected.corp.example", Port: 389},
		{FQDN: "failed.corp.example", Port: 389},
	}})
	for _, event := range []observe.TraceEvent{
		{Kind: observe.ConnectionTrace, Protocol: "ldap", Server: "connected.corp.example:389", Outcome: observe.Success},
		{Kind: observe.ExchangeTrace, Protocol: "ldap", Server: "failed.corp.example:389", Outcome: observe.Failed},
	} {
		event.Phase, event.Duration = observe.TraceCompleted, time.Millisecond
		report.Trace(t.Context(), event)
	}
	data, err := report.TestMessage("self@corp.example", []string{"self@corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	message, err := netmail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	bodies, jsonData := testmailContents(t, message)
	var snapshot jsonTestReport
	if err := json.Unmarshal(jsonData, &snapshot); err != nil {
		t.Fatal(err)
	}
	for _, item := range snapshot.Tables {
		if item.ID == "dc_observations" {
			t.Fatalf("JSON contains DC rows without latency: %+v", item)
		}
	}
	if !strings.Contains(string(jsonData), noDCResponseLatencies) {
		t.Fatal("JSON omitted the no-latency explanation")
	}
	for format, body := range bodies {
		if strings.Contains(body, "connected.corp.example") || strings.Contains(body, "failed.corp.example") ||
			!strings.Contains(body, noDCResponseLatencies) {
			t.Fatalf("%s did not apply latency-only filtering:\n%s", format, body)
		}
	}
}

func TestTestmailJSONMinimalReport(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	data, err := report.TestMessage("self@corp.example", []string{"self@corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	message, err := netmail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	_, jsonData := testmailContents(t, message)
	var snapshot jsonTestReport
	if err := json.Unmarshal(jsonData, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Tables) != 1 || snapshot.Tables[0].ID != "summary" {
		t.Fatalf("minimal testmail must always attach its summary: %+v", snapshot.Tables)
	}
}
