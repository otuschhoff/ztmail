package mail

import (
	"encoding/json"
	"html"
	"io"
	"strings"
	"testing"
	"time"
)

func FuzzDomainFormatting(f *testing.F) {
	for _, seed := range []string{"", "<script>&\"'", "user@CORP.EXAMPLE", "dc.corp.example.evil",
		"dc.corp.example-other", "\x00\xff", "<span style=\"color:#6b7280\">@corp.example</span>"} {
		f.Add(seed, "corp.example")
	}
	f.Fuzz(func(t *testing.T, value, domain string) {
		normalized, err := DNSName(domain)
		if err != nil {
			return
		}
		plain := formatDomain(value, reportPlain, true, normalized)
		uncolored := formatDomain(value, reportTerminal, false, normalized)
		if plain != value || uncolored != value {
			t.Fatal("uncolored formatting changed the value")
		}
		styled := formatDomain(value, reportHTML, false, normalized)
		stripped := strings.ReplaceAll(styled, `<span style="color:#6b7280">`, "")
		stripped = strings.ReplaceAll(stripped, "</span>", "")
		if stripped != html.EscapeString(value) {
			t.Fatal("HTML formatting changed text or introduced unescaped markup")
		}
	})
}

func FuzzReportJSONSchema(f *testing.F) {
	f.Add("schema fixture: <script>&", false)
	f.Add("schema fixture: \x00\xff@corp.example", true)
	f.Fuzz(func(t *testing.T, value string, debug bool) {
		r := NewTestReport(io.Discard, false)
		r.started = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		r.snapshotAt = r.started.Add(time.Second)
		r.debug = debug
		r.rows = []reportRow{{"FAIL", "Fuzz check", value}}
		tables := r.reportTables()
		data, err := r.jsonSnapshotTables(tables)
		if err != nil {
			t.Fatal(err)
		}
		var snapshot jsonTestReport
		if err := json.Unmarshal(data, &snapshot); err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		keys := []string{"schema_version", "snapshot_at", "snapshot_phase", "notes", "tables", "authentication"}
		if len(fields) != len(keys) {
			t.Fatal("JSON wire field count changed")
		}
		for _, key := range keys {
			if _, ok := fields[key]; !ok {
				t.Fatalf("required JSON wire field missing: %s", key)
			}
		}
		if snapshot.SchemaVersion != 2 || snapshot.SnapshotPhase != "after_transport_authentication_before_data" ||
			!snapshot.SnapshotAt.Equal(r.snapshotAt) || snapshot.Authentication.Method != AuthGSSAPI {
			t.Fatal("snapshot contract changed")
		}
		wantIDs := []string{"summary", "issues"}
		if debug {
			wantIDs = append(wantIDs, "runtime", "tls", "authentication", "crypto", "validity")
		}
		if len(snapshot.Tables) != len(wantIDs) {
			t.Fatalf("table count=%d, want %d", len(snapshot.Tables), len(wantIDs))
		}
		for i, table := range snapshot.Tables {
			if table.ID != wantIDs[i] || table.Title == "" || len(table.Columns) == 0 {
				t.Fatalf("table shape changed at %d: %+v", i, table)
			}
			for _, row := range table.Rows {
				if len(row) != len(table.Columns) {
					t.Fatalf("ragged schema table %s", table.ID)
				}
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var normalized string
		if err := json.Unmarshal(encoded, &normalized); err != nil {
			t.Fatal(err)
		}
		issue := snapshot.Tables[1]
		if len(issue.Columns) != 2 || issue.Columns[0] != "Check" || issue.Columns[1] != "Result / details" {
			t.Fatal("issue wire columns changed")
		}
		if len(issue.Rows) != 1 || len(issue.Rows[0]) != 2 ||
			issue.Rows[0][0] != "[FAIL] Fuzz check" || issue.Rows[0][1] != normalized {
			t.Fatalf("issue content changed: %+v", issue.Rows)
		}
		for _, format := range []reportFormat{reportPlain, reportHTML, reportTerminal} {
			if tables.issues.render(format, false, "corp.example") == "" {
				t.Fatal("nonempty issue table rendered empty")
			}
		}
	})
}
