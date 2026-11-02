package mail

import (
	"fmt"
	"html"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
)

type reportFormat int

const (
	reportTerminal reportFormat = iota
	reportPlain
	reportHTML
)

type reportTable struct {
	header  table.Row
	rows    []table.Row
	configs []table.ColumnConfig
}

func (t reportTable) render(format reportFormat) string {
	if format == reportTerminal {
		writer := table.NewWriter()
		writer.SetStyle(table.StyleRounded)
		writer.SetColumnConfigs(t.configs)
		if t.header != nil {
			writer.AppendHeader(t.header)
		}
		writer.AppendRows(t.rows)
		return writer.Render()
	}
	var result strings.Builder
	if format == reportHTML {
		result.WriteString(`<table style="border-collapse:collapse;width:100%;margin:12px 0">`)
		if t.header != nil {
			result.WriteString("<tr>")
			for _, label := range t.header {
				result.WriteString(`<th scope="col" style="text-align:left;padding:8px;border:1px solid #d1d5db;background:#f3f4f6">` +
					html.EscapeString(fmt.Sprint(label)) + "</th>")
			}
			result.WriteString("</tr>")
		}
	}
	for i, row := range t.rows {
		if format == reportPlain {
			if i > 0 && len(row) > 2 {
				result.WriteByte('\n')
			}
			if t.header == nil {
				fmt.Fprintf(&result, "%v: %v\n", row[0], row[1])
			} else {
				for j, cell := range row {
					fmt.Fprintf(&result, "%v: %v\n", t.header[j], cell)
				}
			}
			continue
		}
		result.WriteString("<tr>")
		for j, cell := range row {
			tag, scope := "td", ""
			if t.header == nil && j == 0 {
				tag, scope = "th", ` scope="row"`
			}
			result.WriteString("<" + tag + scope + ` style="text-align:left;vertical-align:top;padding:8px;border:1px solid #d1d5db;white-space:pre-wrap">` +
				html.EscapeString(fmt.Sprint(cell)) + "</" + tag + ">")
		}
		result.WriteString("</tr>")
	}
	if format == reportHTML {
		result.WriteString("</table>")
	}
	return strings.TrimSuffix(result.String(), "\n")
}

func reportNote(format reportFormat, value string) string {
	if format == reportHTML {
		return "<p>" + html.EscapeString(value) + "</p>"
	}
	return value
}
