package mail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/otuschhoff/adbind/ad/dns"
	"github.com/otuschhoff/adbind/ad/observe"
)

type TestReport struct {
	mu        sync.Mutex
	output    io.Writer
	outputErr error
	exchanges int
	verbose   bool
}

func NewTestReport(output io.Writer, verbose bool) *TestReport {
	return &TestReport{output: output, verbose: verbose}
}

func (r *TestReport) Line(status, step, detail string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.outputErr != nil {
		return
	}
	_, r.outputErr = fmt.Fprintf(r.output, "[%s] %s: %s\n", status, step, detail)
}

func (r *TestReport) Step(step string, err error, detail string) {
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

func (r *TestReport) Finish(err *error) {
	r.Line("INFO", "Endpoint visibility", "Only observed exchanges identify used servers. Cache hits emit no exchange; Windows SSPI KDC traffic is OS-managed and not observable.")
	r.mu.Lock()
	count := r.exchanges
	outputErr := r.outputErr
	r.mu.Unlock()
	*err = errors.Join(*err, outputErr)
	r.Step("Test", *err, fmt.Sprintf("authentication checks completed; %d AD exchanges observed; no email sent", count))
	r.mu.Lock()
	defer r.mu.Unlock()
	if outputErr == nil {
		*err = errors.Join(*err, r.outputErr)
	}
}
