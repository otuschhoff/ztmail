package mail

import (
	"context"
	"io"
	"time"
)

type Config struct {
	Relay, Hello, SPN, From, TLSMode string
	Port                             int
	Timeout                          time.Duration
	Test                             bool
	Report                           *TestReport
	Warning                          func(error)
}

type options struct {
	relay, hello, spn, from, tlsMode string
	port                             int
	timeout                          time.Duration
	testMode                         bool
	report                           *TestReport
	warning                          func(error)
}

func Deliver(ctx context.Context, c Config, recipients []string, message []byte, backend Backend, log io.Writer) error {
	return deliver(ctx, options{relay: c.Relay, hello: c.Hello, spn: c.SPN, from: c.From,
		tlsMode: c.TLSMode, port: c.Port, timeout: c.Timeout, testMode: c.Test, report: c.Report, warning: c.Warning},
		recipients, message, backend, log)
}
