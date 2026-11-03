package mail

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/kerberos"
)

func TestValidityDateFormattingAt48HourBoundary(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 34, 56, 0, time.UTC)
	for _, tt := range []struct {
		name     string
		distance time.Duration
		want     string
	}{
		{"past-outside", -48*time.Hour - time.Nanosecond, "2026-11-01"},
		{"past-exact", -48 * time.Hour, "2026-11-01 12:34"},
		{"past-inside", -48*time.Hour + time.Nanosecond, "2026-11-01 12:34"},
		{"now", 0, "2026-11-03 12:34"},
		{"future-inside", 48*time.Hour - time.Nanosecond, "2026-11-05 12:34"},
		{"future-exact", 48 * time.Hour, "2026-11-05 12:34"},
		{"future-outside", 48*time.Hour + time.Nanosecond, "2026-11-05"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			field := testMetadataField(now.Add(tt.distance), kerberos.MetadataTicket)
			if got := validityTime(field, now); got != tt.want {
				t.Fatalf("date=%q, want %q", got, tt.want)
			}
		})
	}
	for _, field := range []kerberos.MetadataField[time.Time]{
		{Reason: kerberos.MetadataNotProvided},
		{Available: true},
	} {
		if got := validityTime(field, now); !strings.HasPrefix(got, "Unavailable (") {
			t.Fatalf("unavailable/zero timestamp was formatted as a date: %q", got)
		}
	}
}

func TestValiditySameDayDimmingUsesUTCSnapshotAndKeepsTimeNormal(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	report.snapshotAt = time.Date(2034, 1, 5, 23, 30, 0, 0, time.UTC).In(time.FixedZone("east", 2*60*60))
	report.tlsValidity = []certificateValidity{{
		label: "Certificate",
		start: time.Date(2034, 1, 5, 23, 0, 0, 0, time.UTC).In(time.FixedZone("east", 2*60*60)),
		end:   time.Date(2034, 1, 6, 0, 15, 0, 0, time.UTC).In(time.FixedZone("west", -10*60*60)),
	}}
	source := report.validityTable()
	row := securityTableRow(t, source, "Certificate")
	if row[1] != "2034-01-05 23:00" || row[2] != "2034-01-06 00:15" {
		t.Fatalf("validity dates were not normalized to UTC: %v", row)
	}
	html := source.render(reportHTML, false, "")
	for _, want := range []string{
		htmlMonospace(`<span style="color:#6b7280">2034-01-05</span> 23:00`),
		htmlMonospace(`<span style="color:#6b7280">2034-01-</span>06 00:15`),
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("same-day HTML date/time styling missing %q:\n%s", want, html)
		}
	}
	terminal := source.render(reportTerminal, true, "")
	if !strings.Contains(terminal, "\x1b[90m2034-01-05\x1b[0m 23:00") ||
		!strings.Contains(terminal, "\x1b[90m2034-01-\x1b[0m06 00:15") ||
		strings.Contains(terminal, "\x1b[90m2034-01-06") {
		t.Fatalf("date-only terminal dimming is incorrect:\n%q", terminal)
	}
	for _, format := range []reportFormat{reportPlain, reportTerminal} {
		unstyled := source.render(format, false, "")
		if strings.Contains(unstyled, "\x1b") || strings.Contains(unstyled, "<span") ||
			!strings.Contains(unstyled, "2034-01-05 23:00") {
			t.Fatalf("unstyled date changed: %s", unstyled)
		}
	}
	if row[1] != "2034-01-05 23:00" || row[2] != "2034-01-06 00:15" {
		t.Fatal("styled rendering mutated raw validity values")
	}
}

func TestValidityDateDimmingMatchesCalendarComponents(t *testing.T) {
	now := time.Date(2034, 6, 15, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name, date, prefix, rest string
	}{
		{"same-day", "2034-06-15", "2034-06-15", " 13:00"},
		{"same-month-near", "2034-06-16", "2034-06-", "16 13:00"},
		{"same-month-past", "2034-06-01", "2034-06-", "01"},
		{"same-month-future", "2034-06-30", "2034-06-", "30"},
		{"same-year-past", "2034-01-15", "2034-", "01-15"},
		{"same-year-future", "2034-12-15", "2034-", "12-15"},
		{"different-year-past", "2033-06-15", "", "2033-06-15"},
		{"different-year-future", "2035-06-15", "", "2035-06-15"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			date, err := time.Parse("2006-01-02", tt.date)
			if err != nil {
				t.Fatal(err)
			}
			report := NewTestReport(io.Discard, false)
			report.snapshotAt = now
			report.tlsValidity = []certificateValidity{{label: "Certificate", start: date.Add(13 * time.Hour), end: date.Add(14 * time.Hour)}}
			source := report.validityTable()
			row := securityTableRow(t, source, "Certificate")
			if row[1] != tt.prefix+tt.rest {
				t.Fatalf("raw timestamp=%q, want %q", row[1], tt.prefix+tt.rest)
			}
			htmlValue, terminalValue := tt.rest, tt.rest
			if tt.prefix != "" {
				htmlValue = `<span style="color:#6b7280">` + tt.prefix + "</span>" + tt.rest
				terminalValue = "\x1b[90m" + tt.prefix + "\x1b[0m" + tt.rest
			}
			if html := source.render(reportHTML, false, ""); !strings.Contains(html, htmlMonospace(htmlValue)) {
				t.Fatalf("HTML date prefix mismatch: %s", html)
			}
			if terminal := source.render(reportTerminal, true, ""); !strings.Contains(terminal, terminalValue) {
				t.Fatalf("terminal date prefix mismatch: %q", terminal)
			}
			for _, format := range []reportFormat{reportPlain, reportTerminal} {
				if output := source.render(format, false, ""); strings.Contains(output, "\x1b") ||
					strings.Contains(output, "<span") || !strings.Contains(output, tt.prefix+tt.rest) {
					t.Fatalf("unstyled date changed: %q", output)
				}
			}
		})
	}
}

func TestValidityNewAgeStrictBoundaryAcrossTLSKerberosAndSSPI(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name      string
		elapsed   time.Duration
		wantStart string
		wantAge   string
	}{
		{"zero", 0, "now", "new"},
		{"positive", time.Nanosecond, "now", "new"},
		{"just-below-five", 5*time.Second - time.Nanosecond, "now", "new"},
		{"exact-five", 5 * time.Second, "2026-11-03 11:59", "5.0s"},
		{"just-above-five", 5*time.Second + time.Nanosecond, "2026-11-03 11:59", "5.0s"},
		{"future-nanosecond", -time.Nanosecond, "2026-11-03 12:00", "Starts in 0.0ms"},
		{"future-second", -time.Second, "2026-11-03 12:00", "Starts in 1.0s"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			start := now.Add(-tt.elapsed)
			report := NewTestReport(io.Discard, false)
			report.EnableDebug()
			report.snapshotAt = now
			report.tlsValidity = []certificateValidity{{label: "Certificate", start: start, end: now.Add(8 * time.Hour)}}
			metadata := testTicketMetadata(now)
			metadata.ValidFrom = testMetadataField(start, kerberos.MetadataTicket)
			metadata.Context = kerberos.ContextMetadata{
				ValidFrom: testMetadataField(start, kerberos.MetadataSSPIContext),
				Expires:   testMetadataField(now.Add(8*time.Hour), kerberos.MetadataSSPIContext),
			}
			report.KerberosTicket(metadata)
			source := report.validityTable()
			for i, row := range source.rows {
				if row[1] != tt.wantStart || row[3] != tt.wantAge || row[4] != "+8 hours" {
					t.Fatalf("row %d age/start/remaining mismatch: %v", i, row)
				}
				wantSource := []string{"tls_certificate", string(kerberos.MetadataTicket), string(kerberos.MetadataSSPIContext)}[i]
				if row[5] != wantSource {
					t.Fatalf("row %d provenance changed: %v", i, row)
				}
			}
			if len(source.rows) != 3 {
				t.Fatalf("expected TLS, ticket and SSPI rows, got %d", len(source.rows))
			}
			html := source.render(reportHTML, false, "")
			terminal := source.render(reportTerminal, true, "")
			if tt.wantAge == "new" {
				if !strings.Contains(html, `<span style="color:#6b7280">new</span>`) ||
					!strings.Contains(html, htmlMonospace("now")) ||
					!strings.Contains(terminal, "\x1b[90mnew\x1b[0m") {
					t.Fatalf("fresh age/start styling missing: HTML=%s terminal=%q", html, terminal)
				}
			} else if strings.Contains(html, ">new</span>") || strings.Contains(terminal, "\x1b[90mnew") {
				t.Fatalf("non-fresh age styled as new: HTML=%s terminal=%q", html, terminal)
			}
			for _, format := range []reportFormat{reportPlain, reportTerminal} {
				if output := source.render(format, false, ""); strings.Contains(output, "\x1b") ||
					strings.Contains(output, "<span") || !strings.Contains(output, tt.wantAge) {
					t.Fatalf("unstyled age changed: %q", output)
				}
			}
			data, err := report.jsonSnapshot()
			if err != nil {
				t.Fatal(err)
			}
			var snapshot jsonTestReport
			if err := json.Unmarshal(data, &snapshot); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, item := range snapshot.Tables {
				if item.ID != "validity" {
					continue
				}
				found = true
				if len(item.Rows) != 3 {
					t.Fatalf("JSON validity row count=%d", len(item.Rows))
				}
				for _, row := range item.Rows {
					if row[1] != tt.wantStart || row[3] != tt.wantAge {
						t.Fatalf("JSON age/start contains styling or differs from snapshot: %v", row)
					}
				}
			}
			if !found {
				t.Fatal("JSON validity table missing")
			}
		})
	}
}

func TestValidityUnavailableAndInvalidStartNeverBecomeNew(t *testing.T) {
	for _, field := range []kerberos.MetadataField[time.Time]{
		{Reason: kerberos.MetadataNotProvided},
		{Available: true},
	} {
		now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
		report := NewTestReport(io.Discard, false)
		report.snapshotAt = now
		metadata := testTicketMetadata(now)
		metadata.ValidFrom = field
		metadata.Context = kerberos.ContextMetadata{
			ValidFrom: field,
			Expires:   testMetadataField(now.Add(time.Hour), kerberos.MetadataSSPIContext),
		}
		report.KerberosTicket(metadata)
		want := "Unavailable (not_provided)"
		if field.Available {
			want = "Unavailable (invalid timestamp)"
		}
		for _, label := range []string{
			"Kerberos SMTP service ticket (" + metadata.Service.Value + ")",
			"SSPI security context (not ticket validity)",
		} {
			row := securityTableRow(t, report.validityTable(), label)
			if row[1] != want || row[3] != want || row[5] != "-" {
				t.Fatalf("unavailable/invalid start became new or changed provenance: %v", row)
			}
		}
	}
}

func TestValidityJSONUsesSnapshotDatePrecisionWithoutStyling(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	report := NewTestReport(io.Discard, false)
	report.EnableDebug()
	report.snapshotAt = now
	report.tlsValidity = []certificateValidity{{label: "Certificate", start: now.Add(-72 * time.Hour), end: now.Add(time.Hour)}}
	report.KerberosTicket(testTicketMetadata(now))
	report.renderValidity(reportHTML)
	data, err := report.jsonSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot jsonTestReport
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if !snapshot.SnapshotAt.Equal(now) || snapshot.SchemaVersion != 1 {
		t.Fatalf("snapshot metadata changed: %+v", snapshot)
	}
	for _, item := range snapshot.Tables {
		if item.ID != "validity" {
			continue
		}
		row := item.Rows[0]
		if row[1] != "2026-10-31" || row[2] != "2026-11-03 13:00" ||
			strings.Contains(string(data), "<span") || strings.Contains(string(data), "\x1b") {
			t.Fatalf("JSON date precision/styling mismatch: %v", row)
		}
		return
	}
	t.Fatal("JSON validity table missing")
}
