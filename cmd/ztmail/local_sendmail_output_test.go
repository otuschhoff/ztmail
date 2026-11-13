package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/ztmail/internal/mail"
)

type matchingOutputFailure struct {
	match string
	cause error
}

func (w matchingOutputFailure) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.match) {
		return 0, w.cause
	}
	return len(p), nil
}

func TestFallbackAcceptedStatusFailureNeverUncertainOrReplayed(t *testing.T) {
	executable, argsPath, _ := fakeLocalSendmail(t)
	cause := errors.New("accepted status broken")
	o := options{sendmailPath: executable, timeout: time.Second, verbose: true}
	err := sendmailFallback(context.Background(), o, []string{"root"}, nil, "", errADCredentialsUnavailable,
		matchingOutputFailure{match: "Message accepted by host sendmail", cause: cause})
	if !errors.Is(err, mail.ErrAcceptedOutput) || !errors.Is(err, cause) || errors.Is(err, mail.ErrDeliveryUncertain) {
		t.Fatalf("known local acceptance must not be uncertain: %v", err)
	}
	if shouldFallbackToSendmail(context.Background(), o, errors.Join(err, mail.ErrRelayUnavailable)) {
		t.Fatalf("accepted output failure allows fallback/replay: %v", err)
	}
	if data, readErr := os.ReadFile(argsPath); readErr != nil || strings.Count(string(data), "root\n") != 1 {
		t.Fatalf("native submission count wrong: args=%q err=%v", data, readErr)
	}
}

func TestNativeOutputFailureRetainsActualUncertainty(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "writer error", true: "short write"}[short], func(t *testing.T) {
			executable, _, _ := fakeLocalSendmail(t)
			if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf 'status\\n'\nexit 75\n"), 0700); err != nil {
				t.Fatal(err)
			}
			cause := errors.New("native output broken")
			var writer io.Writer = failedReportWriter{cause}
			if short {
				writer, cause = shortOutputWriter{}, io.ErrShortWrite
			}
			err := submitLocalSendmail(context.Background(), executable, "", []string{"root"}, nil, writer)
			if !errors.Is(err, cause) || !errors.Is(err, mail.ErrDeliveryUncertain) || errors.Is(err, mail.ErrAcceptedOutput) {
				t.Fatalf("actual native uncertainty/copy error lost: %v", err)
			}
		})
	}
}
