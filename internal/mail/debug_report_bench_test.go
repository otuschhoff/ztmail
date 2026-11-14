package mail

import (
	"fmt"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/observe"
)

var fixtureEpoch = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

func runtimeBenchmarkFixture(spans int) (*TestReport, map[string]time.Duration) {
	r := &TestReport{started: fixtureEpoch, values: make(map[string]string)}
	r.traces = make([]observe.TraceEvent, 0, spans+1)
	r.traceEnds = make([]time.Time, 0, spans+1)
	expected := make(map[string]time.Duration)
	offset := time.Duration(0)
	for block := 0; block < spans/5; block++ {
		unit := time.Duration(1+block%3) * 100 * time.Microsecond
		for index, span := range []struct {
			operation, protocol string
			start, end          int
		}{
			{"AD client setup", "", 0, 20},
			{"ldap search", "ldap", 2, 18},
			{"service_ticket", "kerberos", 4, 10},
			{"dns lookup", "dns", 6, 8},
			{"SMTP TCP connection", "", 12, 22},
		} {
			id := observe.ScopeID(block*5 + index + 1)
			parent := observe.ScopeID(block*5 + 1)
			if index == 0 {
				parent = 0
			}
			r.traces = append(r.traces, observe.TraceEvent{
				Scope: observe.Scope{ID: id, ParentID: parent}, Kind: observe.OperationTrace, Phase: observe.TraceCompleted,
				Operation: span.operation, Protocol: span.protocol, Outcome: observe.Success,
				Duration: time.Duration(span.end-span.start) * unit,
			})
			r.traceEnds = append(r.traceEnds, fixtureEpoch.Add(offset+time.Duration(span.end)*unit))
		}
		for label, units := range map[string]int{
			"DNS": 2, "Kerberos credentials / tickets": 4, "LDAP": 10,
			"SMTP handshake": 4, "AD setup / orchestration": 2, "Other / untracked": 3,
		} {
			expected[label] += time.Duration(units) * unit
		}
		offset += 25 * unit
	}
	r.snapshotAt = fixtureEpoch.Add(offset)
	return r, expected
}

func BenchmarkRuntimeBreakdownSmall(b *testing.B) {
	for _, spans := range []int{0, 5, 10, 100} {
		b.Run(fmt.Sprintf("spans=%d", spans), func(b *testing.B) {
			r, expected := runtimeBenchmarkFixture(spans)
			b.ReportAllocs()
			for b.Loop() {
				if result := r.runtimeBreakdownTable(); len(result.rows) != len(expected) {
					b.Fatalf("runtime categories=%d, want %d", len(result.rows), len(expected))
				}
			}
		})
	}
}

func BenchmarkRuntimeBreakdownUntracked(b *testing.B) {
	for _, spans := range []int{5, 100} {
		b.Run(fmt.Sprintf("spans=%d", spans), func(b *testing.B) {
			r, _ := runtimeBenchmarkFixture(spans)
			for i := range r.traces {
				r.traces[i].Operation, r.traces[i].Protocol = "untracked", ""
			}
			b.ReportAllocs()
			for b.Loop() {
				if result := r.runtimeBreakdownTable(); len(result.rows) != 1 {
					b.Fatalf("runtime categories=%d, want only untracked time", len(result.rows))
				}
			}
		})
	}
}

func BenchmarkRuntimeBreakdown(b *testing.B) {
	for _, spans := range []int{1000, 2000, 4000} {
		b.Run(fmt.Sprintf("spans=%d", spans), func(b *testing.B) {
			r, _ := runtimeBenchmarkFixture(spans)
			b.ReportAllocs()
			for b.Loop() {
				result := r.runtimeBreakdownTable()
				if len(result.rows) != 6 {
					b.Fatalf("runtime categories=%d, want 6", len(result.rows))
				}
			}
		})
	}
}

func TestBenchmarkRuntimeFixture(t *testing.T) {
	for _, spans := range []int{1000, 2000, 4000} {
		t.Run(fmt.Sprintf("spans=%d", spans), func(t *testing.T) {
			r, expected := runtimeBenchmarkFixture(spans)
			if len(r.traces) != spans || len(r.traceEnds) != spans {
				t.Fatal("fixture lost spans or completion times")
			}
			var expectedTotal time.Duration
			for _, duration := range expected {
				expectedTotal += duration
			}
			if expectedTotal != r.snapshotAt.Sub(r.started) {
				t.Fatal("category totals do not partition the wall timeline")
			}
			result := r.runtimeBreakdownTable()
			if len(result.rows) != len(expected) {
				t.Fatalf("categories=%d, want %d", len(result.rows), len(expected))
			}
			seen := make(map[string]bool)
			var displayedTotal, roundingBound time.Duration
			for _, row := range result.rows {
				label, value := fmt.Sprint(row[0]), fmt.Sprint(row[1])
				duration, ok := expected[label]
				if !ok || seen[label] || value != formatDuration(duration) {
					t.Fatalf("category %q=%q, want %q (known=%t)", label, value, formatDuration(duration), ok)
				}
				seen[label] = true
				parsed, err := time.ParseDuration(value)
				if err != nil || parsed <= 0 {
					t.Fatalf("invalid category duration %q: %v", value, err)
				}
				displayedTotal += parsed
				if duration >= time.Second {
					roundingBound += 50 * time.Millisecond
				} else {
					roundingBound += 50 * time.Microsecond
				}
			}
			if delta := displayedTotal - expectedTotal; delta < -roundingBound || delta > roundingBound {
				t.Fatalf("displayed durations do not sum to wall time: delta=%s", delta)
			}
		})
	}
}
