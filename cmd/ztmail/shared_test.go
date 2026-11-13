package main

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/otuschhoff/ztmail/internal/mail"
)

func TestAcceptedCleanupOutputFailure(t *testing.T) {
	for _, owner := range []string{"credential", "DNS owner"} {
		for _, short := range []bool{false, true} {
			t.Run(owner+map[bool]string{false: "/error", true: "/short"}[short], func(t *testing.T) {
				cleanup := errors.New("owner cleanup failed")
				cause := errors.New("warning output failed")
				var writer io.Writer = failedReportWriter{cause}
				if short {
					writer, cause = shortOutputWriter{}, io.ErrShortWrite
				}
				err := reportAcceptedCleanup(writer, nil, owner, cleanup)
				if !errors.Is(err, mail.ErrAcceptedOutput) || !errors.Is(err, cause) || !errors.Is(err, cleanup) ||
					errors.Is(err, mail.ErrDeliveryUncertain) {
					t.Fatalf("known accepted cleanup/output failures lost: %v", err)
				}
			})
		}
		var output strings.Builder
		if err := reportAcceptedCleanup(&output, nil, owner, errors.New("cleanup failed")); err != nil ||
			!strings.Contains(output.String(), owner+" cleanup failed") {
			t.Fatalf("successful cleanup warning changed behavior: %v %q", err, output.String())
		}
	}
}
