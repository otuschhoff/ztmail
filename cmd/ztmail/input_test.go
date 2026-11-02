package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type startedReader struct {
	io.Reader
	started chan struct{}
}

func (r *startedReader) Read(p []byte) (int, error) {
	select {
	case <-r.started:
	default:
		close(r.started)
	}
	return r.Reader.Read(p)
}

func TestMessageInputCancellation(t *testing.T) {
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	reader := &startedReader{Reader: input, started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, _, err := prepareMessageContext(ctx, reader, nil, "corp.example", false, false)
		done <- err
	}()
	select {
	case <-reader.started:
	case <-time.After(3 * time.Second):
		t.Fatal("message read did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not interrupt message input")
	}
}

func TestMessageInputPreservesParsing(t *testing.T) {
	for _, ignoreDots := range []bool{false, true} {
		message := "To: recipient@corp.example\nSubject: test\n\nbody\n.\n"
		expected, recipients, err := prepareMessage(strings.NewReader(message), nil, "corp.example", true, ignoreDots)
		if err != nil {
			t.Fatal(err)
		}
		got, gotRecipients, err := prepareMessageContext(context.Background(), strings.NewReader(message), nil, "corp.example", true, ignoreDots)
		if err != nil || string(got) != string(expected) || strings.Join(gotRecipients, ",") != strings.Join(recipients, ",") {
			t.Fatalf("changed input parsing: message=%q recipients=%v err=%v", got, gotRecipients, err)
		}
	}
	readErr := errors.New("input failed")
	_, _, err := prepareMessageContext(context.Background(), inputErrorReader{readErr}, nil, "corp.example", false, false)
	if !errors.Is(err, readErr) {
		t.Fatalf("lost read error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := prepareMessageContext(ctx, failingReader{}, nil, "corp.example", false, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled read: %v", err)
	}
}

type inputErrorReader struct{ err error }

func (r inputErrorReader) Read([]byte) (int, error) { return 0, r.err }
