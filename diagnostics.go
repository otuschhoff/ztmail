package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/otuschhoff/adbind/ad/observe"
)

type testReport struct {
	mu        sync.Mutex
	output    io.Writer
	outputErr error
	exchanges int
}

func newTestReport(output io.Writer) *testReport {
	return &testReport{output: output}
}

func (r *testReport) line(status, step, detail string) {
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

func (r *testReport) step(step string, err error, detail string) {
	if err != nil {
		r.line("FAIL", step, err.Error())
	} else {
		r.line("OK", step, detail)
	}
}

func (r *testReport) operation(_ context.Context, event observe.Event) {
	r.line(strings.ToUpper(string(event.Outcome)), "AD SDK "+event.Operation, event.Duration.String())
}

func (r *testReport) exchange(_ context.Context, event observe.ExchangeEvent) {
	r.mu.Lock()
	r.exchanges++
	r.mu.Unlock()
	r.line(strings.ToUpper(string(event.Outcome)), "AD exchange", fmt.Sprintf(
		"protocol=%q request=%q server=%q peer=%q transport=%q duration=%s (exchange result, not authentication proof)",
		event.Protocol, event.Request, event.Server, event.Address, event.Transport, event.Duration))
}

func (r *testReport) finish(err *error) {
	r.line("INFO", "Endpoint visibility", "Only observed exchanges identify used servers. Cache hits emit no exchange; Windows SSPI KDC traffic is OS-managed and not observable.")
	r.mu.Lock()
	count := r.exchanges
	outputErr := r.outputErr
	r.mu.Unlock()
	*err = errors.Join(*err, outputErr)
	r.step("Test", *err, fmt.Sprintf("authentication checks completed; %d AD exchanges observed; no email sent", count))
	r.mu.Lock()
	defer r.mu.Unlock()
	if outputErr == nil {
		*err = errors.Join(*err, r.outputErr)
	}
}
