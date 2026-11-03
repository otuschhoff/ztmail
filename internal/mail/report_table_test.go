package mail

import (
	"reflect"
	"strings"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
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
		{"User", `a<&@CORP.EXAMPLE`, htmlMonospace(`a&lt;&amp;<span style="color:#6b7280">@CORP.EXAMPLE</span>`)},
		{"Hostname", "relay.corp.example.attacker.test", htmlMonospace("relay.corp.example.attacker.test")},
		{"Hostname", "relay.corp.example-other.test", htmlMonospace("relay.corp.example-other.test")},
		{"Replies", "-", `<span style="color:#6b7280">-</span>`},
		{"Avg response", "-", `<span style="color:#6b7280">-</span>`},
	} {
		if got := formatReportCell(tc.value, tc.key, reportHTML, false, "corp.example"); got != tc.want {
			t.Errorf("%s %q: got %q, want %q", tc.key, tc.value, got, tc.want)
		}
		if got := formatReportCell(tc.value, tc.key, reportPlain, true, "corp.example"); got != tc.value {
			t.Errorf("plain value changed: %q", got)
		}
		if got := formatReportCell("-", "Replies", reportTerminal, true, ""); got != "\x1b[90m-\x1b[0m" {
			t.Errorf("missing grey terminal placeholder: %q", got)
		}
		if got := formatReportCell("-", "Replies", reportTerminal, false, ""); got != "-" {
			t.Errorf("unstyled terminal placeholder changed: %q", got)
		}
	}

}

func TestTechnicalHTMLCellsAndEmbeddedNames(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"AD domain", "corp.example"}, {"User", "alice@CORP.EXAMPLE"}, {"SPN", "smtp/relay"},
		{"Mail (from)", "alice@corp.example"}, {"Port", "587"}, {"Subject", "CN=AD CA, O=Example"},
		{"Cipher suite", "TLS_AES_256_GCM_SHA384"}, {"Key exchange", "X25519MLKEM768"},
		{"Certificate signature", "SHA256-RSA"}, {"Kerberos ticket encryption", "AES256-CTS-HMAC-SHA1-96; enctype=18"},
	} {
		got := formatReportCell(tc.value, tc.key, reportHTML, false, "corp.example")
		if !strings.HasPrefix(got, `<code style="font-family:`) || !strings.HasSuffix(got, "</code>") {
			t.Errorf("%q not monospace: %s", tc.key, got)
		}
		if got := formatReportCell(tc.value, tc.key, reportPlain, true, "corp.example"); got != tc.value {
			t.Errorf("plain value changed: %q", got)
		}
	}
	value := "[WARN] Use smtp/relay.corp.example for alice@corp.example on 192.0.2.1:587; TLS_AES_256_GCM_SHA384"
	got := formatReportCell(value, "", reportHTML, false, "corp.example")
	for _, want := range []string{`<span style="color:#a16207">[WARN] Use `,
		htmlMonospace(`smtp/relay<span style="color:#6b7280">.corp.example</span>`),
		htmlMonospace(`alice<span style="color:#6b7280">@corp.example</span>`),
		htmlMonospace("192.0.2.1:587"), htmlMonospace("TLS_AES_256_GCM_SHA384")} {
		if !strings.Contains(got, want) {
			t.Errorf("missing coloured technical content %q: %s", want, got)
		}
	}
	got = formatReportCell("Mail Jörg$@corp.example", "", reportHTML, false, "corp.example")
	if !strings.Contains(got, htmlMonospace(`Jörg$<span style="color:#6b7280">@corp.example</span>`)) {
		t.Fatalf("Unicode or machine-account principal was not monospace: %s", got)
	}
	got = formatReportCell("OK (CN=<smtp>; verified; TLS1.3)", "Transport security", reportHTML, false, "")
	if !strings.HasPrefix(got, `<strong style="color:#15803d">OK</strong> (`) ||
		!strings.Contains(got, htmlMonospace("CN=&lt;smtp&gt;")) ||
		!strings.Contains(got, htmlMonospace("TLS1.3")) || strings.Contains(got, "<smtp>") {
		t.Fatalf("CN, TLS escaping or green OK lost: %s", got)
	}
	report := reportTable{header: table.Row{"Property", "Cryptography"}, rows: []table.Row{{"Cipher suite", "TLS_AES_128_GCM_SHA256"}}}
	if !strings.Contains(report.render(reportHTML, false, ""), htmlMonospace("TLS_AES_128_GCM_SHA256")) {
		t.Fatal("technical property metadata was not propagated by table rendering")
	}
}

func TestNumericColumnAlignment(t *testing.T) {
	report := reportTable{header: table.Row{"Name", "Replies", "Response", "Mixed", "Missing"},
		rows: []table.Row{{"one", "2", "7ms", "5", "-"}, {"two", "-", "-", "label", "-"},
			{"three", "12", "100ms", "6", "-"}},
		configs: []table.ColumnConfig{{Number: 2, WidthMin: 8}}}
	if got, want := report.numericColumns(), []bool{false, true, true, true, false}; !reflect.DeepEqual(got, want) {
		t.Fatalf("numeric columns=%v, want %v", got, want)
	}

	html := report.render(reportHTML, false, "")
	for _, want := range []string{`text-align:right;padding:8px;border:1px solid #d1d5db;background:#f3f4f6">Replies`,
		`text-align:right;vertical-align:top;padding:8px;border:1px solid #d1d5db;white-space:pre-wrap">2`,
		`text-align:right;vertical-align:top;padding:8px;border:1px solid #d1d5db;white-space:pre-wrap">label`} {
		if !strings.Contains(html, want) {
			t.Errorf("missing HTML alignment %q:\n%s", want, html)
		}
	}
	terminal := report.render(reportTerminal, false, "")
	if !strings.Contains(terminal, "│        2 │") || !strings.Contains(terminal, "│      7ms │") {
		t.Fatalf("numeric cells not right aligned / width config lost:\n%s", terminal)
	}
	if report.configs[0].Align != 0 {
		t.Fatal("rendering mutated caller's column configs")
	}
}

func TestNumericColumnMajorityAndUnits(t *testing.T) {
	for _, test := range []struct {
		name   string
		values []string
		want   bool
	}{
		{"majority", []string{"1", "2", "label"}, true},
		{"tie", []string{"1", "label"}, false},
		{"mainly-text", []string{"1", "label", "other"}, false},
		{"missing-only", []string{"-", ""}, false},
		{"strength", []string{"~128bit", "~256bit", "Unavailable", "-"}, true},
		{"relative-time", []string{"1 day", "+69 days", "Starts in 2 hours", "Expired 1 minute ago"}, true},
		{"relative-short-time", []string{"+30.0s", "Expired 10.0ms ago", "+<1 minute"}, true},
		{"non-finite", []string{"NaN", "Inf", "-Inf"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := reportTable{header: table.Row{"Value"}}
			for _, value := range test.values {
				report.rows = append(report.rows, table.Row{value})
			}
			if got := report.numericColumns()[0]; got != test.want {
				t.Errorf("got right-aligned=%v, want %v", got, test.want)
			}
		})
	}
}

func TestExplicitSecurityColumnAlignmentInTerminalAndHTML(t *testing.T) {
	report := reportTable{header: table.Row{"NIST strength", "Age", "Remaining", "Details"},
		rows: []table.Row{{"~128bit", "1 day", "+69 days", "metadata"},
			{"Unavailable", "Unavailable", "Unavailable", "metadata"},
			{"Unavailable", "Unavailable", "Unavailable", "metadata"}},
		configs: []table.ColumnConfig{
			{Name: "NIST strength", WidthMin: 20, Align: text.AlignRight, AlignHeader: text.AlignRight},
			{Number: 2, WidthMin: 20, Align: text.AlignRight, AlignHeader: text.AlignRight},
			{Number: 3, WidthMin: 20, Align: text.AlignRight, AlignHeader: text.AlignRight},
		}}
	original := append([]table.ColumnConfig(nil), report.configs...)
	html := report.render(reportHTML, false, "")
	for _, label := range []string{"NIST strength", "Age", "Remaining"} {
		want := `text-align:right;padding:8px;border:1px solid #d1d5db;background:#f3f4f6">` + label
		if !strings.Contains(html, want) {
			t.Errorf("HTML header not right-aligned: %q:\n%s", label, html)
		}
	}
	for _, value := range []string{"~128bit", "1 day", "+69 days", "Unavailable"} {
		want := `text-align:right;vertical-align:top;padding:8px;border:1px solid #d1d5db;white-space:pre-wrap">` + value
		if !strings.Contains(html, want) {
			t.Errorf("HTML cell not right-aligned: %q:\n%s", value, html)
		}
	}
	terminal := report.render(reportTerminal, false, "")
	for _, value := range []string{"~128bit", "1 day", "+69 days", "Unavailable"} {
		want := "│ " + strings.Repeat(" ", 20-len(value)) + value + " │"
		if !strings.Contains(terminal, want) {
			t.Errorf("terminal cell not right-aligned: %q:\n%s", value, terminal)
		}
	}
	if !reflect.DeepEqual(report.configs, original) {
		t.Fatal("rendering changed caller-owned column configs")
	}
}
