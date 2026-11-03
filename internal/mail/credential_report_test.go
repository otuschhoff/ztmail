package mail

import (
	"encoding/json"
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
				want = htmlMonospace(source + ` <span style="color:#6b7280">(` + path + ")</span>")
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

func TestPasswordCredentialSourceYellow(t *testing.T) {
	for _, value := range []string{"password", "PASSWORD"} {
		for _, color := range []bool{false, true} {
			got := formatReportCell(value, "Cred source", reportTerminal, color, "")
			want := value
			if color {
				want = text.FgYellow.EscapeSeq() + value + text.Reset.EscapeSeq()
			}
			if got != want {
				t.Errorf("color=%t password source=%q, want %q", color, got, want)
			}
			want = htmlMonospace(`<span style="color:#a16207">` + value + "</span>")
			if got := formatReportCell(value, "Cred source", reportHTML, color, ""); got != want {
				t.Errorf("HTML color=%t: got %s, want %s", color, got, want)
			}
			if got := formatReportCell(value, "Cred source", reportPlain, color, ""); got != value {
				t.Errorf("plain credential source changed: %q", got)
			}
		}
	}
}

func TestPasswordCredentialFormattingPreservesRawSnapshot(t *testing.T) {
	report := NewTestReport(io.Discard, false)
	report.color = true
	report.Value("Cred source", "password")
	for _, format := range []reportFormat{reportTerminal, reportHTML, reportPlain} {
		report.renderFormat(format)
	}
	data, err := report.jsonSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	var snapshot jsonTestReport
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	for _, row := range snapshot.Tables[0].Rows {
		if row[0] == "Cred source" {
			if row[1] != "password" || report.values["Cred source"] != "password" {
				t.Fatalf("credential formatting changed the raw source: %v", row)
			}
			return
		}
	}
	t.Fatal("JSON summary omitted the credential source")
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
