package mail

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/otuschhoff/adbind/ad/observe"
)

type TestReport struct {
	mu        sync.Mutex
	output    io.Writer
	outputErr error
	exchanges int
}

func NewTestReport(output io.Writer) *TestReport {
	return &TestReport{output: output}
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
	r.Line(strings.ToUpper(string(event.Outcome)), "AD SDK "+event.Operation, event.Duration.String())
}

func (r *TestReport) Exchange(_ context.Context, event observe.ExchangeEvent) {
	r.mu.Lock()
	r.exchanges++
	r.mu.Unlock()
	r.Line(strings.ToUpper(string(event.Outcome)), "AD exchange", fmt.Sprintf(
		"protocol=%q request=%q server=%q peer=%q transport=%q duration=%s (exchange result, not authentication proof)",
		event.Protocol, event.Request, event.Server, event.Address, event.Transport, event.Duration))
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
