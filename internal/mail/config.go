package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"time"
)

type Config struct {
	Relay, Hello, SPN, From, TLSMode string
	Port                             int
	Timeout                          time.Duration
	Test                             bool
	TestMail                         bool
	Report                           *TestReport
	Warning                          func(error)
	Auth                             AuthMode
	ClientCertificate                *tls.Certificate
	ServerTrust                      ServerTrust
	Authentication                   func(AuthenticationResult)
	preparedTrust                    *preparedServerTrust
}

// WithPreparedTrust reuses owned CA parsing, never verification or signer decisions.
// PrepareAuthentication still validates the current public trust input on every call.
func (c Config) WithPreparedTrust(source Config) Config {
	c.preparedTrust = source.preparedTrust
	return c
}

type options struct {
	relay, hello, spn, from, tlsMode string
	port                             int
	timeout                          time.Duration
	testMode                         bool
	testMail                         bool
	report                           *TestReport
	warning                          func(error)
	auth                             AuthMode
	clientCertificate                *tls.Certificate
	serverTrust                      ServerTrust
	authentication                   func(AuthenticationResult)
	preparedTrust                    *preparedServerTrust
}

func Deliver(ctx context.Context, c Config, recipients []string, message []byte, backend Resolver, log io.Writer) error {
	if c.TestMail && (c.Test || c.Report == nil) {
		return errors.New("testmail requires a report and cannot be combined with no-email test mode")
	}
	var err error
	c, err = PrepareAuthentication(c)
	if err != nil {
		return err
	}
	return deliver(ctx, options{relay: c.Relay, hello: c.Hello, spn: c.SPN, from: c.From,
		tlsMode: c.TLSMode, port: c.Port, timeout: c.Timeout, testMode: c.Test, testMail: c.TestMail, report: c.Report, warning: c.Warning,
		auth: c.Auth, clientCertificate: c.ClientCertificate, serverTrust: c.ServerTrust, authentication: c.Authentication,
		preparedTrust: c.preparedTrust},
		recipients, message, backend, log)
}
