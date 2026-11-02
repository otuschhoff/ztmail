package mail

import (
	"strings"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
)

func TestReportTableBorderStyles(t *testing.T) {
	report := reportTable{header: table.Row{"Key", "Value"}, rows: []table.Row{
		{"Authentication", "OK"}, {"Hostname", "worker.corp.example"},
	}}
	for _, enabled := range []bool{false, true} {
		result := report.render(reportTerminal, enabled, "corp.example")
		for _, want := range []string{"\x1b[90m╭", "\x1b[90m│", "\x1b[90m├", "\x1b[90m╰"} {
			if strings.Contains(result, want) != enabled {
				t.Errorf("color=%t border style %q:\n%q", enabled, want, result)
			}
		}
		if !enabled && strings.Contains(result, "\x1b") {
			t.Fatalf("uncoloured table contains ANSI escapes: %q", result)
		}
	}
}

func TestReportCellStyles(t *testing.T) {
	for _, tc := range []struct {
		key, value, want string
	}{
		{"Authentication", "OK", `<strong style="color:#15803d">OK</strong>`},
		{"Transport security", "FAILED: rejected", `<span style="color:#b91c1c">FAILED: rejected</span>`},
		{"Transport security", "TLS off", `<span style="color:#0891b2">TLS off</span>`},
		{"User", `a<&@CORP.EXAMPLE`, `a&lt;&amp;<span style="color:#6b7280">@CORP.EXAMPLE</span>`},
		{"Hostname", "relay.corp.example.attacker.test", "relay.corp.example.attacker.test"},
		{"Hostname", "relay.corp.example-other.test", "relay.corp.example-other.test"},
	} {
		if got := formatReportCell(tc.value, tc.key, reportHTML, false, "corp.example"); got != tc.want {
			t.Errorf("%s %q: got %q, want %q", tc.key, tc.value, got, tc.want)
		}
		if got := formatReportCell(tc.value, tc.key, reportPlain, true, "corp.example"); got != tc.value {
			t.Errorf("plain value changed: %q", got)
		}
	}
}
