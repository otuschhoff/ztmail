package mail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	netmail "net/mail"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/discovery"
	"github.com/otuschhoff/adbind/ad/observe"
)

var testMessageBenchmarkCases = []struct {
	name         string
	observations int
	debug        bool
}{
	{"small", 10, false},
	{"medium", 100, false},
	{"debug_rich", 1000, true},
}

func testMessageBenchmarkFixture(observations int, debug bool) *TestReport {
	r := &TestReport{output: io.Discard, started: fixtureEpoch, values: make(map[string]string),
		authentication: AuthenticationResult{Method: AuthGSSAPI}}
	r.Value("Authentication method", "GSSAPI")
	r.Value("Authentication", "OK")
	r.Value("AD domain", "corp.example")
	r.Value("Hostname", "worker.corp.example")
	r.Value("Canonical mail", "self@corp.example")
	r.Value("User", "synthetic@corp.example")
	r.Value("Transport security", "TLS off")
	for i := 0; i < observations; i++ {
		r.rows = append(r.rows, reportRow{"WARN", fmt.Sprintf("Synthetic check %04d", i),
			fmt.Sprintf("Observation %04d: dc.corp.example:389; user%d@corp.example; <offline & synthetic>", i, i)})
	}
	if debug {
		r.EnableDebug()
		r.verbose = true
		timeline, _ := runtimeBenchmarkFixture(observations)
		r.traces, r.traceEnds = timeline.traces, timeline.traceEnds
		r.Inventory(discovery.InventoryEvent{Advertised: []discovery.Endpoint{{FQDN: "dc.corp.example", Port: 389}}})
		for i := range r.traces {
			if r.traces[i].Protocol == "ldap" {
				r.traces[i].Kind = observe.ExchangeTrace
				r.traces[i].Server = "dc.corp.example:389"
				r.traces[i].Response = true
			}
		}
	}
	return r
}

func BenchmarkTestMessage(b *testing.B) {
	for _, size := range testMessageBenchmarkCases {
		b.Run(fmt.Sprintf("%s/observations=%d", size.name, size.observations), func(b *testing.B) {
			r := testMessageBenchmarkFixture(size.observations, size.debug)
			recipients := []string{"recipient@corp.example"}
			traceCount := len(r.traces)
			b.ReportAllocs()
			for b.Loop() {
				data, err := r.TestMessage("", recipients)
				if err != nil || len(data) == 0 {
					b.Fatalf("test message: bytes=%d, error=%v", len(data), err)
				}
				// Measure appends a preparation trace after the snapshot; keep input size fixed.
				b.StopTimer()
				r.traces = r.traces[:traceCount]
				r.traceEnds = r.traceEnds[:traceCount]
				b.StartTimer()
			}
		})
	}
}

func TestBenchmarkTestMessageFixture(t *testing.T) {
	for _, size := range testMessageBenchmarkCases {
		t.Run(fmt.Sprintf("%s/observations=%d", size.name, size.observations), func(t *testing.T) {
			r := testMessageBenchmarkFixture(size.observations, size.debug)
			if len(r.rows) != size.observations || (size.debug && len(r.traces) != size.observations) {
				t.Fatal("fixture observation counts are incorrect")
			}
			data, err := r.TestMessage("", []string{"recipient@corp.example"})
			if err != nil {
				t.Fatal(err)
			}
			message, err := netmail.ReadMessage(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			bodies, attachment := testmailContents(t, message)
			var snapshot jsonTestReport
			if err := json.Unmarshal(attachment, &snapshot); err != nil {
				t.Fatal(err)
			}
			date, err := netmail.ParseDate(message.Header.Get("Date"))
			if err != nil || !date.Equal(snapshot.SnapshotAt.Truncate(time.Second)) ||
				snapshot.SchemaVersion != 2 || snapshot.SnapshotPhase != "after_transport_authentication_before_data" {
				t.Fatalf("incoherent snapshot metadata: date=%v err=%v snapshot=%+v", date, err, snapshot)
			}
			if message.Header.Get("From") != "<self@corp.example>" ||
				message.Header.Get("To") != "<recipient@corp.example>" || message.Header.Get("Message-ID") == "" {
				t.Fatal("incorrect message headers")
			}
			tables := make(map[string]jsonReportTable)
			for _, item := range snapshot.Tables {
				if _, exists := tables[item.ID]; exists || item.Title == "" || len(item.Columns) == 0 {
					t.Fatalf("invalid table metadata: %+v", item)
				}
				tables[item.ID] = item
				for _, row := range item.Rows {
					if len(row) != len(item.Columns) {
						t.Fatalf("invalid table row shape: %+v", item)
					}
					if item.ID == "summary" || item.ID == "runtime" {
						if !strings.Contains(bodies["text/plain"], row[0]+": "+row[1]) {
							t.Fatalf("JSON and plain snapshot differ: %v", row)
						}
					}
					if item.ID == "summary" && row[0] == "Total runtime" &&
						row[1] != formatDuration(snapshot.SnapshotAt.Sub(r.started)) {
						t.Fatal("runtime did not use the shared snapshot")
					}
				}
			}
			if len(tables["issues"].Rows) != size.observations {
				t.Fatal("snapshot lost observations")
			}
			if size.debug {
				for _, id := range []string{"runtime", "dc_observations", "step_timings", "tls", "authentication", "crypto", "validity"} {
					if _, ok := tables[id]; !ok {
						t.Fatalf("debug table missing: %s", id)
					}
				}
				if len(tables["step_timings"].Rows) != size.observations ||
					len(r.traces) != size.observations+1 || len(tables["dc_observations"].Rows) != 1 {
					t.Fatal("snapshot included preparation trace or lost DC observations")
				}
			} else if len(tables) != 2 {
				t.Fatal("non-debug snapshot contains debug tables")
			}
			last := fmt.Sprintf("Observation %04d:", size.observations-1)
			for kind, body := range bodies {
				if !strings.Contains(body, last) || !strings.Contains(body, "before sending this message") ||
					strings.Contains(body, "Runtime breakdown") != size.debug ||
					strings.ContainsAny(body, "\x1b╭╮╰╯│─") {
					t.Fatalf("incorrect %s body shape", kind)
				}
			}
			if !strings.HasPrefix(bodies["text/html"], "<!doctype html>") ||
				!strings.HasSuffix(bodies["text/html"], "</body></html>") ||
				!strings.Contains(bodies["text/html"], "&lt;offline &amp; synthetic&gt;") ||
				!strings.Contains(bodies["text/plain"], "<offline & synthetic>") {
				t.Fatal("HTML document or plain fallback lost escaping")
			}
		})
	}
}
