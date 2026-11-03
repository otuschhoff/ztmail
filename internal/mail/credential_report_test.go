package mail

import (
	"io"
	"strings"
	"testing"

	"github.com/jedib0t/go-pretty/v6/text"
)

func TestCredentialPathFormattingAndReportOrder(t *testing.T) {
	for _, source := range []string{"keytab", "ccache"} {
		report := NewTestReport(io.Discard, false)
		report.Value("Cred source", source)
		report.Value("Cred source path", `/credentials/mail<&>.file`)
		for _, format := range []reportFormat{reportTerminal, reportPlain, reportHTML} {
			result := report.renderFormat(format)
			path := `/credentials/mail<&>.file`
			if format == reportHTML {
				path = `/credentials/mail&lt;&amp;&gt;.file`
			}
			want := source + " (" + path + ")"
			if format == reportHTML {
				want = source + ` <span style="color:#6b7280">(` + path + ")</span>"
			}
			if !strings.Contains(result, want) {
				t.Errorf("format=%v source=%s missing path:\n%s", format, source, result)
			}
			previous := -1
			for _, key := range []string{"AD domain", "User", "Mail (from)", "Cred source", "Authentication method", "SPN"} {
				index := strings.Index(result, key)
				if index < 0 || index <= previous {
					t.Errorf("format=%v: incorrect order at %q:\n%s", format, key, result)
				}
				previous = index
			}
		}

		if report.values["Cred source"] != source {
			t.Fatal("rendering changed raw credential source")
		}
	}
}

func TestCredentialPathColor(t *testing.T) {
	for _, source := range []string{"ccache", "keytab"} {
		path := `/credentials/user@corp.example (backup).file`
		value := source + " (" + path + ")"
		for _, color := range []bool{false, true} {
			got := formatReportCell(value, "Cred source", reportTerminal, color, "corp.example")
			want := value
			if color {
				want = source + " " + text.FgHiBlack.EscapeSeq() + "(" + path + ")" + text.Reset.EscapeSeq()
			}
			if got != want {
				t.Errorf("source=%s color=%v: got %q, want %q", source, color, got, want)
			}
			if got := formatReportCell(value, "Cred source", reportPlain, color, "corp.example"); got != value {
				t.Errorf("plain text source=%s color=%v: got %q, want %q", source, color, got, value)
			}
		}
	}
}
