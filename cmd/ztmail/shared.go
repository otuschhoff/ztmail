package main

import (
	"context"
	"crypto/tls"
	"io"
	"net/netip"

	"github.com/otuschhoff/ztmail/internal/mail"
)

type securityContext = mail.SecurityContext
type submissionBackend = mail.Backend
type testReport = mail.TestReport

var newTestReport = mail.NewTestReport
var prepareMessage = mail.PrepareMessage
var applySender = mail.ApplySender
var envelopeAddress = mail.EnvelopeAddress
var canonicalMail = mail.CanonicalMail
var dnsName = mail.DNSName

func (s *adSession) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	addresses, err := (&mail.ADBackend{Client: s.client, Lease: s.lease}).Resolve(ctx, host)
	if err != nil {
		s.diagnoseDNS(ctx, err)
	}
	return addresses, err
}

func (s *adSession) NewSecurityContext(ctx context.Context, spn string, state *tls.ConnectionState) (securityContext, error) {
	return (&mail.ADBackend{Client: s.client, Lease: s.lease}).NewSecurityContext(ctx, spn, state)
}

func deliver(ctx context.Context, o options, recipients []string, message []byte, backend submissionBackend, log io.Writer) error {
	return mail.Deliver(ctx, mail.Config{Relay: o.relay, Hello: o.hello, SPN: o.spn, From: o.from,
		TLSMode: o.tlsMode, Port: o.port, Timeout: o.timeout, Test: o.testMode, TestMail: o.testMail, Report: o.report},
		recipients, message, backend, log)
}
