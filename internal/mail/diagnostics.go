package mail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/otuschhoff/adbind/ad/addns"
	"github.com/otuschhoff/adbind/ad/discovery"
	"github.com/otuschhoff/adbind/ad/dns"
	"github.com/otuschhoff/adbind/ad/observe"
	"golang.org/x/term"
)

type TestReport struct {
	mu        sync.Mutex
	output    io.Writer
	outputErr error
	exchanges int
	verbose   bool
	color     bool
	rows      []reportRow
	values    map[string]string
	started   time.Time
	debug     bool
	traces    []observe.TraceEvent
	traceEnds []time.Time
	testMail  bool
	inventory []discovery.InventoryEvent
}

type reportRow struct {
	status, step, detail string
}

func NewTestReport(output io.Writer, verbose bool) *TestReport {
	color := false
	if file, ok := output.(*os.File); ok {
		color = term.IsTerminal(int(file.Fd())) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	}
	return &TestReport{output: output, verbose: verbose, color: color, started: time.Now(),
		values: map[string]string{"Authentication method": "GSSAPI"}}
}

func (r *TestReport) Line(status, step, detail string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if importantResult(status, step) {
		r.rows = append(r.rows, reportRow{status, step, detail})
	}
	if r.verbose && r.outputErr == nil {
		_, r.outputErr = fmt.Fprintf(r.output, "[%s] %s: %s\n", status, step, detail)
	}
}

func importantResult(status, step string) bool {
	if strings.HasPrefix(step, "AD SDK ") || step == "AD exchange" {
		return false
	}
	if step == "DNS" {
		return status == "FAIL"
	}
	if status == "FAIL" || status == "WARN" || status == "SKIP" {
		return true
	}
	switch step {
	case "Host/domain discovery", "Target configuration", "Message submission", "Borrowed AD owner",
		"Authenticated AD identity", "Credential identity", "Canonical AD mail lookup",
		"SMTP service ticket", "Relay DNS lookup", "SMTP TCP connection", "SMTP STARTTLS",
		"Implicit TLS", "GSSAPI mutual authentication", "GSSAPI SASL negotiation",
		"SMTP AUTH GSSAPI", "SMTP QUIT", "DNS failure diagnostics", "Test":
		return true
	}
	return false
}

func (r *TestReport) Step(step string, err error, detail string) {
	if r != nil {
		switch step {
		case "SMTP STARTTLS", "Implicit TLS":
			value := detail
			if err != nil {
				value = "FAILED: " + err.Error()
			}
			r.Value("Transport security", value)
		case "SMTP AUTH GSSAPI":
			value := "OK"
			if err != nil {
				value = "FAILED: " + err.Error()
			}
			r.Value("Authentication", value)
		}
	}
	if err != nil {
		r.Line("FAIL", step, err.Error())
	} else {
		r.Line("OK", step, detail)
	}
}

func (r *TestReport) Operation(_ context.Context, event observe.Event) {
	if !r.verbose && (strings.HasPrefix(event.Operation, "dns.") || strings.HasPrefix(event.Operation, "addns.")) {
		return
	}
	r.Line(strings.ToUpper(string(event.Outcome)), "AD SDK "+event.Operation, event.Duration.String())
}

func (r *TestReport) Exchange(_ context.Context, event observe.ExchangeEvent) {
	r.mu.Lock()
	r.exchanges++
	r.mu.Unlock()
	if event.Protocol == "dns" && !r.verbose {
		return
	}
	r.Line(strings.ToUpper(string(event.Outcome)), "AD exchange", fmt.Sprintf(
		"protocol=%q request=%q server=%q peer=%q transport=%q duration=%s (exchange result, not authentication proof)",
		event.Protocol, event.Request, event.Server, event.Address, event.Transport, event.Duration))
}

func (r *TestReport) DNSSummary(event dns.SummaryEvent) {
	status := "FAIL"
	switch event.Outcome {
	case dns.SummaryAnswered:
		status = "OK"
	case dns.SummaryNotFound, dns.SummaryNoData:
		status = "INFO"
	}
	winner := "none"
	if event.Winner.Server.IsValid() {
		winner = fmt.Sprintf("%s transport=%s", event.Winner.Server, event.Winner.Transport)
	}
	detail := fmt.Sprintf("name=%q type=%s duration=%s winner=%s servers_queried=%d outcome=%s purpose=%s",
		event.Name, strings.TrimPrefix(event.Type.String(), "Type"), event.Duration, winner,
		event.ServersQueried, event.Outcome, event.Purpose)
	if !event.Winner.Server.IsValid() && len(event.Responses) > 0 {
		responders := make([]string, 0, len(event.Responses))
		for _, response := range event.Responses {
			responders = append(responders, fmt.Sprintf("%s/%s", response.Server, response.Transport))
		}
		detail += " responders=[" + strings.Join(responders, ", ") + "]"
	}
	if r.verbose {
		detail += fmt.Sprintf(" lookup_id=%d question_id=%d operation=%q attempts=%d",
			event.LookupID, event.QuestionID, event.Operation, event.Attempts)
		for _, response := range event.Responses {
			detail += fmt.Sprintf(" response={server=%s peer=%q transport=%s rcode=%s}",
				response.Server, response.Address, response.Transport, response.RCode)
		}
	}
	r.Line(status, "DNS", detail)
}

func (r *TestReport) DNSDiagnostic(result addns.DiagnosticResult) {
	detail := fmt.Sprintf("original_failure=%s", result.Failure)
	if result.Skip != addns.DiagnosticNotSkipped {
		detail += fmt.Sprintf(" ran=%t skipped=%s duration=%s", result.Ran, result.Skip, result.Duration)
	} else {
		detail += fmt.Sprintf(" ran=%t outcome=%s server=%s transport=%s duration=%s attempts=%d",
			result.Ran, result.Outcome, result.Server, result.Transport, result.Duration, result.Attempts)
	}
	if r.verbose {
		detail += fmt.Sprintf(" lookup_id=%d question_id=%d original_question_id=%d peer=%q probe_failure=%s",
			result.LookupID, result.QuestionID, result.Original.QuestionID, result.Address, result.ProbeFailure)
	}
	r.Line("INFO", "DNS failure diagnostics", detail+" (supplementary evidence only; original lookup failure retained)")
}

func (r *TestReport) Finish(err *error) {
	r.Line("INFO", "Endpoint visibility", "Only observed exchanges identify used servers. Cache hits emit no exchange; Windows SSPI KDC traffic is OS-managed and not observable.")
	r.mu.Lock()
	count := r.exchanges
	outputErr := r.outputErr
	r.mu.Unlock()
	*err = errors.Join(*err, outputErr)
	detail := fmt.Sprintf("authentication checks completed; %d AD exchanges observed; no email sent", count)
	if r.testMail {
		detail = fmt.Sprintf("testmail checks completed; %d AD exchanges observed; delivery status shown separately", count)
	}
	r.Step("Test", *err, detail)
	if *err != nil {
		r.mu.Lock()
		if r.values["Authentication"] == "" {
			r.values["Authentication"] = "Not completed: " + (*err).Error()
		}
		r.mu.Unlock()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if outputErr == nil {
		*err = errors.Join(*err, r.outputErr)
	}
	if r.outputErr == nil {
		_, writeErr := fmt.Fprintln(r.output, r.render())
		*err = errors.Join(*err, writeErr)
	}
}

func (r *TestReport) render() string {
	return r.renderFormat(reportTerminal)
}

func (r *TestReport) renderFormat(format reportFormat) string {
	t := reportTable{configs: []table.ColumnConfig{{Number: 2, WidthMax: 76, WidthMaxEnforcer: text.WrapSoft}}}
	keys := []string{"Hostname", "Target relay", "AD domain", "Mail (from)", "Authentication method"}
	if strings.EqualFold(r.values["Authentication method"], "GSSAPI") {
		keys = append(keys, "User", "Cred source", "SPN")
	}
	keys = append(keys, "Transport security", "Authentication", "Total runtime")
	for _, key := range keys {
		value := r.values[key]
		if value == "" {
			value = "Not reached / unavailable"
		}
		if key == "Total runtime" {
			value = time.Since(r.started).Round(time.Millisecond).String()
		}
		t.rows = append(t.rows, table.Row{key, value})
	}
	result := t.render(format, r.color, r.values["AD domain"])
	// Failures and warnings must remain visible even if authentication succeeded.
	if issues := r.renderIssues(format); issues != "" {
		result += "\n" + issues
	}
	if r.debug {
		result += "\n" + r.renderDebug(format)
	}
	if format != reportTerminal {
		return result
	}
	if r.testMail {
		delivery := r.values["Testmail delivery"]
		if delivery == "" {
			delivery = "Not confirmed; consult the error before retrying."
		}
		return result + "\nTestmail delivery: " + delivery
	}
	return result + "\nNo email sent."
}

func (r *TestReport) renderIssues(format reportFormat) string {
	t := reportTable{header: table.Row{"Check", "Result / details"}, configs: []table.ColumnConfig{
		{Number: 1, WidthMax: 36, WidthMaxEnforcer: text.WrapSoft},
		{Number: 2, WidthMax: 76, WidthMaxEnforcer: text.WrapSoft},
	}}
	if format == reportPlain {
		t.header = nil
	}
	count := 0
	for _, row := range r.rows {
		if row.status != "FAIL" && row.status != "WARN" && row.status != "SKIP" && row.step != "DNS failure diagnostics" {
			continue
		}
		count++
		label := "[" + row.status + "] " + row.step
		t.rows = append(t.rows, table.Row{label, row.detail})
	}
	if count == 0 {
		return ""
	}
	return t.render(format, r.color, r.values["AD domain"])
}
