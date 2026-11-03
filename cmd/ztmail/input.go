package main

import (
	"context"
	"fmt"
	"io"

	"github.com/otuschhoff/ztmail/internal/mail"
)

func prepareMessageContext(ctx context.Context, in io.Reader, recipients []string, domain string, readHeaders, ignoreDots bool) ([]byte, []string, error) {
	return prepareMessageReadContext(ctx, func() ([]byte, []string, error) {
		return prepareMessage(in, recipients, domain, readHeaders, ignoreDots)
	})
}

func prepareLocalMessageContext(ctx context.Context, in io.Reader, recipients []string, readHeaders, ignoreDots bool) ([]byte, []string, error) {
	return prepareMessageReadContext(ctx, func() ([]byte, []string, error) {
		return mail.PrepareLocalMessage(in, recipients, readHeaders, ignoreDots)
	})
}

func prepareMessageReadContext(ctx context.Context, read func() ([]byte, []string, error)) ([]byte, []string, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("read message: %w", err)
	}
	type result struct {
		message    []byte
		recipients []string
		err        error
	}
	done := make(chan result, 1)
	// Arbitrary readers cannot be interrupted safely. Keep the read isolated
	// from submission; on cancellation the CLI exits without waiting for stdin.
	go func() {
		message, recipients, err := read()
		done <- result{message, recipients, err}
	}()
	select {
	case <-ctx.Done():
		return nil, nil, fmt.Errorf("read message: %w", ctx.Err())
	case read := <-done:
		if err := ctx.Err(); err != nil {
			return nil, nil, fmt.Errorf("read message: %w", err)
		}
		return read.message, read.recipients, read.err
	}
}
