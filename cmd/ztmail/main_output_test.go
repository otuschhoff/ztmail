package main

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/otuschhoff/ztmail/internal/mail"
)

func TestInitialDiagnosticOutputFailureBeforeDiscoveryAndCredentials(t *testing.T) {
	for _, mode := range []string{"--test", "--testmail"} {
		for _, short := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/error", true: "/short"}[short], func(t *testing.T) {
				isolatedSenderConfig(t)
				cause := errors.New("initial diagnostic output broken")
				var writer io.Writer = failedReportWriter{cause}
				if short {
					writer, cause = shortOutputWriter{}, io.ErrShortWrite
				}
				cmd := newCommand()
				cmd.SetArgs([]string{mode, "--verbose", "--domain=invalid domain", "--cred-source=ccache", "--ccache=missing"})
				cmd.SetErr(writer)
				cmd.SetIn(failingReader{})
				err := cmd.Execute()
				if !errors.Is(err, cause) || !errors.Is(err, mail.ErrOutputFailed) ||
					errors.Is(err, errADCredentialsUnavailable) || strings.Contains(err.Error(), "invalid domain") {
					t.Fatalf("discovery/acquisition happened after initial output failure: %v", err)
				}
				if strings.Count(err.Error(), cause.Error()) != 1 {
					t.Fatalf("deferred output checkpoints repeated cause: %v", err)
				}
			})
		}
	}
}
