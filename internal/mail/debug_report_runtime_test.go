package mail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	netmail "net/mail"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/observe"
)

func TestRuntimeSMTPAuthenticationClassification(t *testing.T) {
	for _, protocol := range []string{"", "smtp"} {
		for _, operation := range []string{"SMTP GSSAPI authentication", "SMTP EXTERNAL authentication"} {
			t.Run(operation+"/"+protocol, func(t *testing.T) {
				if got := runtimeCategory(observe.TraceEvent{Operation: operation, Protocol: protocol}); got != runtimeSMTPAuth {
					t.Fatalf("category=%d, want SMTP auth", got)
				}
			})
		}
	}
	for _, operation := range []string{"SMTP authentication setup", "SMTP EXTERNAL authentication cleanup", "SMTP author lookup", "SMTP STARTTLS"} {
		t.Run(operation, func(t *testing.T) {
			if got := runtimeCategory(observe.TraceEvent{Operation: operation, Protocol: "smtp"}); got != runtimeSMTPHandshake {
				t.Fatalf("category=%d, want handshake, not auth", got)
			}
		})
	}
}

func TestRuntimeSMTPAuthenticationRepresentations(t *testing.T) {
	for _, protocol := range []string{"", "smtp"} {
		for _, operation := range []string{"SMTP GSSAPI authentication", "SMTP EXTERNAL authentication", "SMTP STARTTLS"} {
			t.Run(operation+"/"+protocol, func(t *testing.T) {
				report := NewTestReport(io.Discard, false)
				report.EnableDebug()
				report.authentication.TLSEstablished = true
				report.authentication.SMTPAuthConfirmed = true
				switch operation {
				case "SMTP EXTERNAL authentication":
					report.authentication.Method = AuthMTLSExternal
				case "SMTP STARTTLS":
					report.authentication.Method = AuthMTLS
					report.authentication.SMTPAuthConfirmed = false
				}
				report.started = fixtureEpoch
				report.snapshotAt = fixtureEpoch.Add(200 * time.Millisecond)
				report.traces = []observe.TraceEvent{{
					Kind: observe.OperationTrace, Phase: observe.TraceCompleted,
					Operation: operation, Protocol: protocol, Duration: 100 * time.Millisecond,
				}}
				report.traceEnds = []time.Time{fixtureEpoch.Add(100 * time.Millisecond)}
				want, absent := "SMTP auth", "SMTP handshake"
				if operation == "SMTP STARTTLS" {
					want, absent = absent, want
				}
				checkText := func(name, text string) {
					t.Helper()
					start := strings.Index(strings.ToLower(text), "runtime breakdown")
					if start < 0 {
						t.Errorf("%s: missing runtime breakdown", name)
						return
					}
					runtime := text[start:]
					runtime, _, _ = strings.Cut(runtime, "DC observations")
					if !strings.Contains(runtime, want) || !strings.Contains(runtime, "100.0ms") || strings.Contains(runtime, absent) {
						t.Errorf("%s: wrong runtime attribution:\n%s", name, runtime)
					}
				}
				for _, format := range []reportFormat{reportTerminal, reportPlain, reportHTML} {
					checkText(fmt.Sprint(format), report.runtimeBreakdownFormat(format))
				}
				data, err := report.jsonSnapshot()
				if err != nil {
					t.Fatal(err)
				}
				checkRuntime := func(data []byte) {
					t.Helper()
					var snapshot jsonTestReport
					if err := json.Unmarshal(data, &snapshot); err != nil {
						t.Fatal(err)
					}
					if snapshot.Authentication != report.authentication {
						t.Errorf("authentication evidence disagrees with runtime fixture: %+v", snapshot.Authentication)
					}
					rows := diagnosticJSONTable(t, data, "runtime")
					found := false
					for _, row := range rows {
						if row[0] == absent {
							t.Errorf("unexpected runtime row: %v", row)
						}
						if row[0] == want {
							found = true
							if row[1] != "100.0ms" {
								t.Errorf("runtime row=%v, want 100.0ms", row)
							}
						}
					}
					if !found {
						t.Errorf("missing %s runtime row: %v", want, rows)
					}
				}
				checkRuntime(data)
				bodies, attachment := diagnosticMIME(t, report)
				checkText("MIME plain", bodies["text/plain"])
				checkText("MIME HTML", bodies["text/html"])
				checkRuntime(attachment)
			})
		}
	}
}

func diagnosticJSONTable(t *testing.T, data []byte, id string) [][]string {
	t.Helper()
	var snapshot jsonTestReport
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 2 {
		t.Fatalf("schema version=%d, want 2", snapshot.SchemaVersion)
	}
	for _, table := range snapshot.Tables {
		if table.ID == id {
			return table.Rows
		}
	}
	t.Fatalf("missing JSON table %s", id)
	return nil
}

func diagnosticMIME(t *testing.T, report *TestReport) (map[string]string, []byte) {
	t.Helper()
	data, err := report.TestMessage("sender@corp.example", []string{"recipient@corp.example"})
	if err != nil {
		t.Fatal(err)
	}
	message, err := netmail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return testmailContents(t, message)
}
