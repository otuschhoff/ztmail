package mail

import (
	"fmt"
	"html"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
)

type reportFormat int

const (
	reportTerminal reportFormat = iota
	reportPlain
	reportHTML
)

type reportTable struct {
	header         table.Row
	rows           []table.Row
	configs        []table.ColumnConfig
	currentDateUTC string
}

const (
	currentYearDateKey  = "Current-year date (UTC)"
	currentMonthDateKey = "Current-month date (UTC)"
	currentDayDateKey   = "Current-day date (UTC)"
)

func (t reportTable) render(format reportFormat, color bool, domain string) string {
	numeric := t.numericColumns()
	for _, config := range t.configs {
		if config.Align != text.AlignRight {
			continue
		}
		column := config.Number - 1
		if config.Number == 0 {
			for i, name := range t.header {
				if config.Name == fmt.Sprint(name) {
					column = i
					break
				}
			}
		}
		if column >= 0 && column < len(numeric) {
			numeric[column] = true
		}
	}
	if format == reportTerminal {
		writer := table.NewWriter()
		style := table.StyleRounded
		if color {
			style.Color.Border = text.Colors{text.FgHiBlack}
			style.Color.Separator = text.Colors{text.FgHiBlack}
		}
		writer.SetStyle(style)
		configs := append([]table.ColumnConfig(nil), t.configs...)
		for column, right := range numeric {
			if !right {
				continue
			}
			index := -1
			for i, config := range configs {
				if config.Number == column+1 || (config.Number == 0 && column < len(t.header) && config.Name == fmt.Sprint(t.header[column])) {
					index = i
					break
				}
			}
			if index < 0 {
				configs = append(configs, table.ColumnConfig{Number: column + 1})
				index = len(configs) - 1
			}
			configs[index].Align, configs[index].AlignHeader = text.AlignRight, text.AlignRight
		}
		writer.SetColumnConfigs(configs)
		if t.header != nil {
			writer.AppendHeader(t.header)
		}
		for _, row := range t.rows {
			cells := make(table.Row, len(row))
			for j, cell := range row {
				cells[j] = formatReportCell(fmt.Sprint(cell), t.cellKey(row, j), format, color, domain)
			}
			writer.AppendRow(cells)
		}
		return writer.Render()
	}
	var result strings.Builder
	if format == reportHTML {
		result.WriteString(`<div style="border:1px solid #d1d5db;border-radius:10px;overflow:hidden;margin:12px 0">` +
			`<table style="border-collapse:separate;border-spacing:0;border-radius:10px;width:100%">`)
		if t.header != nil {
			result.WriteString("<tr>")
			for column, label := range t.header {
				result.WriteString(`<th scope="col" style="text-align:` + columnAlignment(numeric, column) + `;padding:8px;border:1px solid #d1d5db;background:#f3f4f6">` +
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
			result.WriteString("<" + tag + scope + ` style="text-align:` + columnAlignment(numeric, j) + `;vertical-align:top;padding:8px;border:1px solid #d1d5db;white-space:pre-wrap">` +
				formatReportCell(fmt.Sprint(cell), t.cellKey(row, j), format, color, domain) + "</" + tag + ">")
		}
		result.WriteString("</tr>")
	}
	if format == reportHTML {
		result.WriteString("</table></div>")
	}
	return strings.TrimSuffix(result.String(), "\n")
}

var reportNumericDuration = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]+)?|<1) (?:days?|hours?|minutes?)$`)

func (t reportTable) numericColumns() []bool {
	columns := len(t.header)
	for _, row := range t.rows {
		columns = max(columns, len(row))
	}
	numeric := make([]bool, columns)
	for column := range numeric {
		numbers, labels := 0, 0
		for _, row := range t.rows {
			if column >= len(row) {
				labels++
				continue
			}
			value := strings.TrimSpace(fmt.Sprint(row[column]))
			if value == "" || value == "-" {
				continue
			}
			value = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(value, "Starts in "), "Expired "), " ago")
			number, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimPrefix(value, "~"), "bit"), 64)
			if err == nil && !math.IsNaN(number) && !math.IsInf(number, 0) {
				numbers++
				continue
			}
			if _, err := time.ParseDuration(value); err == nil {
				numbers++
				continue
			}
			if reportNumericDuration.MatchString(value) {
				numbers++
				continue
			}
			labels++
		}
		numeric[column] = numbers > labels
	}
	return numeric
}

func columnAlignment(numeric []bool, column int) string {
	if column < len(numeric) && numeric[column] {
		return "right"
	}
	return "left"
}

func (t reportTable) cellKey(row table.Row, column int) string {
	if t.header == nil && column == 0 {
		return "Property"
	}
	if column == 1 && (t.header == nil || (len(t.header) > 0 && fmt.Sprint(t.header[0]) == "Property")) {
		return fmt.Sprint(row[0])
	}
	if column < len(t.header) {
		key := fmt.Sprint(t.header[column])
		if (key == "Start (UTC)" || key == "End (UTC)") && len(t.currentDateUTC) == 10 {
			value := fmt.Sprint(row[column])
			if strings.HasPrefix(value, t.currentDateUTC) {
				return currentDayDateKey
			}
			if strings.HasPrefix(value, t.currentDateUTC[:8]) {
				return currentMonthDateKey
			}
			if strings.HasPrefix(value, t.currentDateUTC[:5]) {
				return currentYearDateKey
			}
		}
		return key
	}
	return ""
}

func formatReportCell(value, key string, format reportFormat, color bool, domain string) (result string) {
	technical := format == reportHTML && technicalReportCell(key) &&
		value != "-" && value != "" && !strings.HasPrefix(value, "Unavailable") && !strings.HasPrefix(value, "Not reached")
	if technical {
		defer func() { result = htmlMonospace(result) }()
	}
	styled := formatDomain(value, format, color, domain)
	if format == reportHTML && !technical && key != "Property" && key != "Runtime breakdown" && key != "Step" && key != "Check" {
		styled = formatHTMLTechnical(value, domain)
	}
	if format == reportPlain || (format == reportTerminal && !color) {
		return styled
	}
	dimLength := 0
	switch key {
	case currentYearDateKey:
		dimLength = 5
	case currentMonthDateKey:
		dimLength = 8
	case currentDayDateKey:
		dimLength = 10
	}
	if dimLength > 0 && len(value) >= 10 {
		date, rest := value[:dimLength], value[dimLength:]
		if format == reportHTML {
			return `<span style="color:#6b7280">` + html.EscapeString(date) + "</span>" + html.EscapeString(rest)
		}
		return text.FgHiBlack.EscapeSeq() + date + text.Reset.EscapeSeq() + rest
	}
	if key == "Cred source" {
		source, path, found := strings.Cut(value, " (")
		if found && strings.HasSuffix(path, ")") &&
			(strings.EqualFold(source, "ccache") || strings.EqualFold(source, "keytab")) {
			path = "(" + path
			if format == reportHTML {
				return html.EscapeString(source) + ` <span style="color:#6b7280">` + html.EscapeString(path) + "</span>"
			}
			return source + " " + text.FgHiBlack.EscapeSeq() + path + text.Reset.EscapeSeq()
		}
	}
	if value == "-" {
		if format == reportHTML {
			return `<span style="color:#6b7280">-</span>`
		}
		return text.FgHiBlack.EscapeSeq() + "-" + text.Reset.EscapeSeq()
	}
	shade, ansi := "", text.FgCyan
	ok := false
	if key == "Authentication" || key == "Transport security" {
		shade = "#0891b2"
		if strings.Contains(value, "FAILED") {
			shade, ansi = "#b91c1c", text.FgRed
		} else if strings.HasPrefix(value, "WARNING:") || strings.Contains(value, "not independently confirmed") ||
			strings.Contains(value, "not confirmed") || strings.Contains(value, "not presented") {
			shade, ansi = "#a16207", text.FgYellow
		} else if strings.HasPrefix(value, "OK") || strings.Contains(value, "verified") {
			shade, ansi = "#15803d", text.FgGreen
			ok = strings.HasPrefix(value, "OK")
		}
	} else if key == "Cred source" && strings.EqualFold(value, "password") {
		shade, ansi = "#a16207", text.FgYellow
	} else if key == "Age" && value == "new" {
		shade, ansi = "#6b7280", text.FgHiBlack
	} else if strings.HasPrefix(value, "[FAIL] ") {
		shade, ansi = "#b91c1c", text.FgRed
	} else if strings.HasPrefix(value, "[WARN] ") || strings.HasPrefix(value, "[SKIP] ") {
		shade, ansi = "#a16207", text.FgYellow
	} else if strings.HasPrefix(value, "[INFO] ") {
		shade = "#0891b2"
	}
	if shade == "" {
		return styled
	}
	if ok {
		if format == reportHTML {
			return `<strong style="color:` + shade + `">OK</strong>` + strings.TrimPrefix(styled, "OK")
		}
		return text.Bold.EscapeSeq() + ansi.EscapeSeq() + "OK" + text.Reset.EscapeSeq() + strings.TrimPrefix(styled, "OK")
	}
	if format == reportHTML {
		return `<span style="color:` + shade + `">` + styled + "</span>"
	}
	return ansi.EscapeSeq() + styled + text.Reset.EscapeSeq()
}

func technicalReportCell(key string) bool {
	switch key {
	case "AD domain", "Realm", "User", "Mail (from)", "Mail", "SPN", "Hostname", "Relay", "Target relay", "Port",
		"Client certificate subject", "Client certificate issuer", "Client certificate SHA256", "Client certificate key",
		"Client certificate signature", "Server trust anchor SHA256", "Server root mode", "Authentication method",
		"Cred source", "Discovered DC / service", "Protocol", "TLS version", "Subject", "Issuer",
		"Subject alternative names", "Cipher suite", "Key exchange", "Certificate key",
		"Certificate signature", "Kerberos ticket encryption", "Kerberos ticket session key",
		"SSPI context protection", "Start (UTC)", "End (UTC)", currentYearDateKey, currentMonthDateKey, currentDayDateKey, "Start source", "Scope / parent":
		return true
	default:
		return false
	}
}

var reportTechnicalName = regexp.MustCompile(
	`CN=(?:"[^"]*"|[^,;()\n]+)` +
		`|[\p{L}\p{N}_.$+-]+(?:/[\p{L}\p{N}_.$+-]+)*@[[:alnum:]_.-]+` +
		`|\[[0-9a-fA-F:]+\](?::[0-9]+)?` +
		`|(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?` +
		`|[[:alnum:]_+-]+(?:\.[[:alnum:]_+-]+)*\.[a-zA-Z][[:alnum:]_-]*(?::[0-9]+)?` +
		`|(?i:smtp|ldap|host|HTTP|cifs|krbtgt|MSSQLSvc)/[[:alnum:]_.+-]+` +
		`|\b(?:TLS[ _]?v?1\.[23]|TLS_[A-Z0-9_]+|AES[0-9][A-Za-z0-9_-]*|` +
		`(?:RSA|ECDSA|Ed25519|X25519|SecP|P-)[A-Za-z0-9_-]*|SHA[0-9][A-Za-z0-9_-]*)\b`,
)

func htmlMonospace(styled string) string {
	return `<code style="font-family:Consolas,&#39;Liberation Mono&#39;,monospace;font-size:inherit">` + styled + "</code>"
}

func formatHTMLTechnical(value, domain string) string {
	var result strings.Builder
	last := 0
	for _, match := range reportTechnicalName.FindAllStringIndex(value, -1) {
		result.WriteString(formatDomain(value[last:match[0]], reportHTML, false, domain))
		result.WriteString(htmlMonospace(formatDomain(value[match[0]:match[1]], reportHTML, false, domain)))
		last = match[1]
	}
	result.WriteString(formatDomain(value[last:], reportHTML, false, domain))
	return result.String()
}

func formatDomain(value string, format reportFormat, color bool, domain string) string {
	escape := func(value string) string {
		if format == reportHTML {
			return html.EscapeString(value)
		}
		return value
	}
	if domain == "" || format == reportPlain || (format == reportTerminal && !color) {
		return escape(value)
	}
	re := regexp.MustCompile(`(?i)[.@]` + regexp.QuoteMeta(domain) + `\b`)
	var result strings.Builder
	last := 0
	for _, match := range re.FindAllStringIndex(value, -1) {
		if match[1] < len(value) && (value[match[1]] == '.' || value[match[1]] == '-') {
			continue
		}
		result.WriteString(escape(value[last:match[0]]))
		part := escape(value[match[0]:match[1]])
		if format == reportHTML {
			result.WriteString(`<span style="color:#6b7280">` + part + "</span>")
		} else {
			result.WriteString(text.FgHiBlack.EscapeSeq() + part + text.Reset.EscapeSeq())
		}
		last = match[1]
	}
	result.WriteString(escape(value[last:]))
	return result.String()
}

func reportNote(format reportFormat, value string) string {
	if format == reportHTML {
		return "<p>" + formatHTMLTechnical(value, "") + "</p>"
	}
	return value
}
