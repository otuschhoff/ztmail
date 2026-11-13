package main

import (
	"context"
	"io"
	"net/netip"
	"os/user"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/ztmail/internal/mail"
)

type dnsOwner interface {
	mail.Resolver
	Close(context.Context) error
}

type adDNSOwner struct{ *adclient.Client }

func (o adDNSOwner) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	return (mail.ADResolver{Client: o.Client}).Resolve(ctx, host)
}

type commandDependencies struct {
	discoverHost func(context.Context, string) (string, string, error)
	currentUser  func() (*user.User, error)
	openTerminal func() (passwordTerminal, error)
	attemptAD    func(context.Context, options, adclient.ADOptions) (*adSession, error)
	newDNSOwner  func(adclient.ADOptions) (dnsOwner, error)
	deliver      func(context.Context, options, []string, []byte, submissionBackend, io.Writer) error
	fallback     func(context.Context, options, []string, []byte, string, error, io.Writer) error
}

func systemDependencies() commandDependencies {
	return commandDependencies{
		discoverHost: discoverHost,
		currentUser:  user.Current,
		openTerminal: openPasswordTerminal,
		attemptAD:    openADAttempt,
		newDNSOwner: func(settings adclient.ADOptions) (dnsOwner, error) {
			client, err := adclient.NewAD(settings)
			if err != nil {
				return nil, err
			}
			return adDNSOwner{Client: client}, nil
		},
		deliver:  deliver,
		fallback: sendmailFallback,
	}
}
