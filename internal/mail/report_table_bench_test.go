package mail

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jedib0t/go-pretty/v6/table"
)

func domainBenchmarkFixture(fragments int) string {
	parts := make([]string, fragments)
	for i := range parts {
		switch i % 4 {
		case 0:
			parts[i] = fmt.Sprintf("dc%d.corp.example:389", i)
		case 1:
			parts[i] = fmt.Sprintf("user%d@CORP.EXAMPLE", i)
		case 2:
			parts[i] = fmt.Sprintf("relay%d.corp.example.attacker.test", i)
		case 3:
			parts[i] = fmt.Sprintf("node%d.corp.example-other.test<&>", i)
		}
	}
	return strings.Join(parts, "; ")
}

var domainBenchmarkFormats = []struct {
	name   string
	format reportFormat
	color  bool
}{
	{"plain", reportPlain, false},
	{"terminal_color", reportTerminal, true},
	{"html", reportHTML, false},
}

func BenchmarkFormatDomain(b *testing.B) {
	for _, fragments := range []int{10, 100, 1000} {
		for _, mode := range domainBenchmarkFormats {
			b.Run(fmt.Sprintf("%s/fragments=%d", mode.name, fragments), func(b *testing.B) {
				value := domainBenchmarkFixture(fragments)
				b.ReportAllocs()
				for b.Loop() {
					result := formatDomain(value, mode.format, mode.color, "corp.example")
					if len(result) < len(value) {
						b.Fatal("domain formatting lost input")
					}
				}
			})
		}
	}
}

func BenchmarkReportTableRender(b *testing.B) {
	for _, fragments := range []int{10, 100, 1000} {
		for _, mode := range domainBenchmarkFormats {
			b.Run(fmt.Sprintf("%s/fragments=%d", mode.name, fragments), func(b *testing.B) {
				value := domainBenchmarkFixture(fragments)
				report := reportTable{header: table.Row{"Step", "Replies"}, rows: []table.Row{{value, "12"}}}
				b.ReportAllocs()
				for b.Loop() {
					result := report.render(mode.format, mode.color, "corp.example")
					if len(result) < len(value) {
						b.Fatal("table rendering lost input")
					}
				}
			})
		}
	}
}

func TestBenchmarkDomainFixture(t *testing.T) {
	for _, fragments := range []int{10, 100, 1000} {
		t.Run(fmt.Sprintf("fragments=%d", fragments), func(t *testing.T) {
			value := domainBenchmarkFixture(fragments)
			if len(strings.Split(value, "; ")) != fragments {
				t.Fatal("incorrect fragment count")
			}
			if got := formatDomain(value, reportPlain, false, "corp.example"); got != value {
				t.Fatal("plain formatting changed names")
			}
			html := formatDomain(value, reportHTML, false, "corp.example")
			terminal := formatDomain(value, reportTerminal, true, "corp.example")
			matches := (fragments/4)*2 + min(fragments%4, 2)
			if strings.Count(html, `<span style="color:#6b7280">`) != matches ||
				strings.Count(terminal, "\x1b[90m") != matches {
				t.Fatal("domain suffix highlighting did not respect name boundaries")
			}
			for _, want := range []string{
				`dc0<span style="color:#6b7280">.corp.example</span>:389`,
				`user1<span style="color:#6b7280">@CORP.EXAMPLE</span>`,
				"relay2.corp.example.attacker.test", "node3.corp.example-other.test&lt;&amp;&gt;",
			} {
				if !strings.Contains(html, want) {
					t.Fatalf("formatted names missing %q", want)
				}
			}
			for _, mode := range domainBenchmarkFormats {
				t.Run(mode.name, func(t *testing.T) {
					report := reportTable{header: table.Row{"Step", "Replies"}, rows: []table.Row{{value, "12"}}}
					result := report.render(mode.format, mode.color, "corp.example")
					if !strings.Contains(strings.ToLower(result), "step") || !strings.Contains(result, "12") {
						t.Fatal("table lost headers or numeric cell")
					}
					if mode.format == reportHTML && (!strings.Contains(result, html) || !strings.Contains(result, "<table ")) {
						t.Fatal("HTML table lost domain formatting")
					}
					if mode.format == reportPlain && !strings.Contains(result, value) {
						t.Fatal("plain table lost raw values")
					}
				})
			}
		})
	}
}
