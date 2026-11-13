package main

import (
	"errors"
	"io"
	"reflect"
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

func TestCommandOutputFailureStopsAtOwnershipBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, failAt string
		test         bool
		want         []string
		accepted     bool
	}{
		{name: "before-host", failAt: "Message submission", test: true},
		{name: "after-host", failAt: "Host/domain discovery", test: true, want: []string{"host"}},
		{name: "before-AD", failAt: "Target configuration", test: true, want: []string{"host"}},
		{name: "after-AD", failAt: "AD identity selection", test: true, want: []string{"host", "ad:ccache", "release", "close-ad"}},
		{name: "before-delivery", failAt: "Authenticated AD identity", test: true, want: []string{"host", "ad:ccache", "release", "close-ad"}},
		{name: "submission-status", failAt: "Submitting to", want: []string{"host", "stdin", "ad:ccache", "release", "close-ad"}},
		{name: "test-cleanup", failAt: "AD credential cleanup", test: true, want: []string{"host", "ad:ccache", "deliver", "release", "close-ad"}},
		{name: "accepted-status", failAt: "Message accepted by relay", accepted: true,
			want: []string{"host", "stdin", "ad:ccache", "deliver", "release", "close-ad"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatedSenderConfig(t)
			h := newCommandHarness(t)
			cause := errors.New("required command output failed")
			args := []string{"--verbose", "--domain=corp.example", "--from=sender@corp.example"}
			if tc.test {
				args = append(args, "--test")
			} else {
				args = append(args, "recipient@corp.example")
			}
			cmd := newCommandWithDependencies(h.deps)
			cmd.SetArgs(args)
			cmd.SetIn(&stageReader{h: h})
			cmd.SetErr(credentialStageWriter{failAt: tc.failAt, err: cause})
			err := cmd.ExecuteContext(t.Context())
			if !reflect.DeepEqual(h.events, tc.want) || h.releases != h.closes || !errors.Is(err, cause) ||
				errors.Is(err, mail.ErrOutputFailed) == tc.accepted || errors.Is(err, mail.ErrAcceptedOutput) != tc.accepted ||
				errors.Is(err, mail.ErrDeliveryUncertain) {
				t.Fatalf("output failure lost ownership/classification: events=%v want=%v err=%v", h.events, tc.want, err)
			}
			if strings.Count(err.Error(), cause.Error()) != 1 {
				t.Fatalf("repeated output cause: %v", err)
			}
		})
	}
}
