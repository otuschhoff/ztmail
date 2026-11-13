package ztmail_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/otuschhoff/adbind/ad/adclient"
	"github.com/otuschhoff/ztmail"
)

func ExampleClient_Send() {
	send := func(ctx context.Context, appAD *adclient.Client) error {
		mailer, err := ztmail.New(ztmail.Options{AD: appAD, Domain: "corp.example.com"})
		if err != nil {
			return err
		}
		result, err := mailer.Send(ctx, ztmail.Message{
			Recipients: []string{"recipient@example.com"},
			Data:       []byte("Subject: Example\r\n\r\nHello.\r\n"),
		})
		for _, warning := range result.Warnings {
			// Policy/authentication warnings can precede acceptance or an error.
			fmt.Printf("Submission warning: %v\n", warning)
		}
		if err != nil {
			if errors.Is(err, ztmail.ErrDeliveryUncertain) {
				return fmt.Errorf("check relay acceptance before retrying: %w", err)
			}
			return err
		}
		if result.Accepted {
			fmt.Println("Message accepted by relay (not mailbox delivery proof)")
		}
		return nil
	}
	_ = send
}
