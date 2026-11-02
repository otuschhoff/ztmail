package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/adbind/ad/addns"
	"github.com/otuschhoff/adbind/ad/dns"
	"github.com/otuschhoff/adbind/ad/observe"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSFailureDiagnosticReport(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		for _, skip := range []addns.DiagnosticSkipReason{addns.DiagnosticNotSkipped, addns.DiagnosticDeadline} {
			t.Run(fmt.Sprintf("%v/%s", verbose, skip), func(t *testing.T) {
				var output bytes.Buffer
				report := NewTestReport(&output, verbose)
				report.DNSDiagnostic(addns.DiagnosticResult{
					LookupID: 1, QuestionID: 2, Failure: addns.FailureSERVFAIL, Skip: skip,
					Ran: skip == addns.DiagnosticNotSkipped, Outcome: addns.DiagnosticNoData,
					Server: netip.MustParseAddrPort("192.0.2.10:53"), Transport: "udp",
					Address: "192.0.2.10:53", Duration: 12 * time.Millisecond, Attempts: 1,
				})
				if !verbose {
					var err error
					report.Finish(&err)
					if err != nil {
						t.Fatal(err)
					}
				}
				text := output.String()
				for _, want := range []string{"[INFO] DNS failure diagnostics", "original_failure=servfail",
					"duration=12.0ms", "original", "retained"} {
					if !strings.Contains(text, want) {
						t.Errorf("missing %q:\n%s", want, text)
					}
				}
				if strings.Contains(text, "lookup_id=1") != verbose || strings.Contains(text, `peer=`) != verbose {
					t.Fatalf("incorrect diagnostic verbosity:\n%s", text)
				}
				if skip == addns.DiagnosticNotSkipped {
					for _, want := range []string{"ran=true", "outcome=probe_no_data", "server=192.0.2.10:53", "transport=udp"} {
						if !strings.Contains(text, want) {
							t.Fatalf("missing actual probe evidence %q:\n%s", want, text)
						}
					}
				} else if !strings.Contains(text, "ran=false skipped=deadline") || strings.Contains(text, "outcome=") {
					t.Fatalf("skip reported as probe:\n%s", text)
				}
			})
		}
	}
}

func dnsSummaryFixture() dns.SummaryEvent {
	response := dns.SummaryResponse{
		Server: netip.MustParseAddrPort("192.0.2.10:5353"), Address: "192.0.2.10:5353",
		Transport: "udp", RCode: dnsmessage.RCodeSuccess,
	}
	return dns.SummaryEvent{
		LookupID: 10, QuestionID: 11, Operation: "lookup_srv", Purpose: dns.PurposeDiscovery,
		Name: "_ldap._tcp.corp.example.", Type: dnsmessage.TypeSRV, Duration: 42 * time.Millisecond,
		Outcome: dns.SummaryAnswered, Winner: response, Responses: []dns.SummaryResponse{response},
		ServersQueried: 3, Attempts: 4,
	}
}

func TestCompactResultsTable(t *testing.T) {
	var output bytes.Buffer
	report := NewTestReport(&output, false)
	report.Line("INFO", "Message submission", "disabled; no email sent")
	report.Step("SMTP STARTTLS", nil, "verified certificate")
	report.Step("SMTP AUTH GSSAPI", errors.New("535 authentication rejected"), "")
	report.Line("WARN", "Skipped credential identity", "unusable identity")
	report.Step("SMTP greeting", nil, "verbose-only greeting")
	report.Operation(context.Background(), observe.Event{Operation: "credential_acquire", Outcome: observe.Success})
	report.DNSSummary(dnsSummaryFixture())
	if output.Len() != 0 {
		t.Fatal("compact results must be buffered until Finish")
	}
	original := errors.New("authentication failed")
	err := original
	report.Finish(&err)
	if !errors.Is(err, original) {
		t.Fatalf("lost original failure: %v", err)
	}
	rendered := output.String()
	for _, want := range []string{"╭", "╮", "╰", "╯", "CHECK", "RESULT / DETAILS",
		"Transport security", "[FAIL] SMTP AUTH GSSAPI", "535 authentication rejected",
		"[WARN] Skipped credential identity", "[FAIL] Test", "No email sent"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("missing %q:\n%s", want, rendered)
		}
	}
	for _, unwanted := range []string{"\x1b[", "verbose-only", "credential_acquire", "_ldap._tcp"} {
		if strings.Contains(rendered, unwanted) {
			t.Errorf("unexpected detail %q:\n%s", unwanted, rendered)
		}
	}
}

func TestReportTableColoursAreLocal(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		var output bytes.Buffer
		report := NewTestReport(&output, false)
		report.color = enabled
		report.Step("SMTP STARTTLS", nil, "verified")
		report.Step("SMTP AUTH GSSAPI", errors.New("rejected"), "")
		var err error
		report.Finish(&err)
		for _, colour := range []string{"\x1b[32m", "\x1b[31m"} {
			if strings.Contains(output.String(), colour) != enabled {
				t.Fatalf("color=%v missing/unexpected %q:\n%s", enabled, colour, &output)
			}
		}
	}
}

func TestReportDoesNotColourNonTerminalWriters(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var output bytes.Buffer
	report := NewTestReport(&output, false)
	if report.color {
		t.Fatal("non-terminal writer must not enable colour")
	}
	report.Step("SMTP AUTH GSSAPI", nil, "accepted")
	var err error
	report.Finish(&err)
	if err != nil || strings.Contains(output.String(), "\x1b[") {
		t.Fatalf("unexpected error or ANSI escapes: %v\n%s", err, &output)
	}
}

func TestDNSReportVerbosity(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		t.Run(fmt.Sprint(verbose), func(t *testing.T) {
			var output bytes.Buffer
			report := NewTestReport(&output, verbose)
			ctx := context.Background()
			report.Exchange(ctx, observe.ExchangeEvent{Protocol: "dns", Request: "TypeSRV", Outcome: observe.Success})
			report.Operation(ctx, observe.Event{Operation: "dns.lookup", Outcome: observe.Success})
			report.Operation(ctx, observe.Event{Operation: "addns.refresh", Outcome: observe.Success})
			report.DNSSummary(dnsSummaryFixture())
			report.Exchange(ctx, observe.ExchangeEvent{Protocol: "ldap", Outcome: observe.Success})
			report.Operation(ctx, observe.Event{Operation: "credential_acquire", Outcome: observe.Success})
			if !verbose {
				if output.Len() != 0 {
					t.Fatal("compact report emitted low-level events before completion")
				}
				var err error
				report.Finish(&err)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(output.String(), "protocol=") || strings.Contains(output.String(), "_ldap.") {
					t.Fatalf("compact report leaked DNS/SDK details:\n%s", &output)
				}
				return
			}
			text := output.String()
			want := "[OK] DNS: name=\"_ldap._tcp.corp.example.\" type=SRV duration=42.0ms " +
				"winner=192.0.2.10:5353 transport=udp servers_queried=3 outcome=answered purpose=discovery"
			if !strings.Contains(text, want) || strings.Count(text, "] DNS:") != 1 {
				t.Fatalf("missing or duplicate DNS summary:\n%s", text)
			}
			for _, detail := range []string{`protocol="dns"`, "AD SDK dns.lookup", "AD SDK addns.refresh",
				"lookup_id=10", "question_id=11", "attempts=4", `peer="192.0.2.10:5353"`} {
				if strings.Contains(text, detail) != verbose {
					t.Errorf("verbose=%v detail=%q:\n%s", verbose, detail, text)
				}
			}
			for _, detail := range []string{`protocol="ldap"`, "AD SDK credential_acquire"} {
				if !strings.Contains(text, detail) {
					t.Errorf("non-DNS diagnostic hidden: %q", detail)
				}
			}
			var err error
			report.Finish(&err)
			if err != nil || !strings.Contains(output.String(), "2 AD exchanges observed") {
				t.Fatalf("hidden exchanges were not counted: %v\n%s", err, &output)
			}
		})
	}
}

func TestDNSSummaryOutcomesWithoutWinner(t *testing.T) {
	for _, test := range []struct {
		outcome dns.SummaryOutcome
		status  string
	}{
		{dns.SummaryNotFound, "INFO"}, {dns.SummaryNoData, "INFO"},
		{dns.SummaryFailed, "FAIL"}, {dns.SummaryCanceled, "FAIL"}, {dns.SummaryDeadline, "FAIL"},
	} {
		t.Run(string(test.outcome), func(t *testing.T) {
			event := dnsSummaryFixture()
			event.Outcome = test.outcome
			event.Winner = dns.SummaryResponse{}
			event.Responses = nil
			event.ServersQueried, event.Attempts = 0, 0
			var output bytes.Buffer
			NewTestReport(&output, true).DNSSummary(event)
			text := output.String()
			for _, want := range []string{"[" + test.status + "] DNS:", "winner=none", "servers_queried=0",
				"outcome=" + string(test.outcome), "duration=42.0ms"} {
				if !strings.Contains(text, want) {
					t.Errorf("missing %q:\n%s", want, text)
				}
			}
			if strings.Contains(text, "192.0.2.") || strings.Contains(text, "transport=") {
				t.Fatalf("fabricated a winning endpoint:\n%s", text)
			}
		})
	}
}

func TestDNSSummaryConsensusAndIPv6(t *testing.T) {
	event := dnsSummaryFixture()
	event.Outcome = dns.SummaryNotFound
	event.Winner = dns.SummaryResponse{}
	event.Responses = []dns.SummaryResponse{
		{Server: netip.MustParseAddrPort("192.0.2.10:53"), Transport: "udp", RCode: dnsmessage.RCodeNameError},
		{Server: netip.MustParseAddrPort("[2001:db8::10]:5353"), Transport: "tcp", RCode: dnsmessage.RCodeNameError},
	}
	var output bytes.Buffer
	NewTestReport(&output, true).DNSSummary(event)
	if !strings.Contains(output.String(), "winner=none") ||
		!strings.Contains(output.String(), "responders=[192.0.2.10:53/udp, [2001:db8::10]:5353/tcp]") {
		t.Fatalf("consensus was misattributed:\n%s", &output)
	}
	event.Winner = event.Responses[1]
	output.Reset()
	NewTestReport(&output, true).DNSSummary(event)
	if !strings.Contains(output.String(), "winner=[2001:db8::10]:5353 transport=tcp") {
		t.Fatalf("IPv6/TCP endpoint was not preserved:\n%s", &output)
	}
}

func TestDNSSummariesAreConcurrentAndQuestionAttributed(t *testing.T) {
	var output bytes.Buffer
	report := NewTestReport(&output, true)
	var wg sync.WaitGroup
	for index := range 40 {
		wg.Go(func() {
			event := dnsSummaryFixture()
			event.Name = fmt.Sprintf("host%d.corp.example.", index)
			event.Duration = time.Duration(index+1) * time.Millisecond
			event.ServersQueried = index + 1
			report.DNSSummary(event)
		})
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 40 {
		t.Fatalf("got %d summary lines, want 40", len(lines))
	}
	for index := range 40 {
		want := fmt.Sprintf("[OK] DNS: name=\"host%d.corp.example.\" type=SRV duration=%s "+
			"winner=192.0.2.10:5353 transport=udp servers_queried=%d outcome=answered purpose=discovery",
			index, formatDuration(time.Duration(index+1)*time.Millisecond), index+1)
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing intact summary %q", want)
		}
	}
}

type dnsReportFailureWriter struct{ err error }

func (w dnsReportFailureWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDNSSummaryOutputFailureIsReturned(t *testing.T) {
	writeErr := errors.New("DNS summary output failed")
	report := NewTestReport(dnsReportFailureWriter{writeErr}, false)
	report.DNSSummary(dnsSummaryFixture())
	lookupErr := errors.New("lookup failed")
	err := lookupErr
	report.Finish(&err)
	if !errors.Is(err, writeErr) || !errors.Is(err, lookupErr) {
		t.Fatalf("lost report or lookup error: %v", err)
	}
}

func TestDNSDiagnosticOutputFailureIsReturned(t *testing.T) {
	writeErr := errors.New("DNS diagnostic output failed")
	report := NewTestReport(dnsReportFailureWriter{writeErr}, false)
	report.DNSDiagnostic(addns.DiagnosticResult{Skip: addns.DiagnosticDeadline})
	lookupErr := errors.New("original lookup failed")
	err := lookupErr
	report.Finish(&err)
	if !errors.Is(err, writeErr) || !errors.Is(err, lookupErr) {
		t.Fatalf("lost diagnostic output or original lookup error: %v", err)
	}
}

func TestDNSReportWithSDKQuery(t *testing.T) {
	for _, verbose := range []bool{false, true} {
		t.Run(fmt.Sprint(verbose), func(t *testing.T) {
			listener, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			if err := listener.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				buffer := make([]byte, 4096)
				n, peer, err := listener.ReadFrom(buffer)
				if err != nil {
					done <- err
					return
				}
				var query dnsmessage.Message
				if err := query.Unpack(buffer[:n]); err != nil {
					done <- err
					return
				}
				if len(query.Questions) != 1 {
					done <- fmt.Errorf("got %d questions, want 1", len(query.Questions))
					return
				}
				response := dnsmessage.Message{
					Header: dnsmessage.Header{ID: query.ID, Response: true,
						RecursionDesired: query.RecursionDesired, RecursionAvailable: true},
					Questions: query.Questions,
					Answers: []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name,
							Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
						Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 20}},
					}},
				}
				wire, err := response.Pack()
				if err == nil {
					_, err = listener.WriteTo(wire, peer)
				}
				done <- err
			}()
			var output bytes.Buffer
			report := NewTestReport(&output, verbose)
			server := netip.MustParseAddrPort(listener.LocalAddr().String())
			client, err := dns.New(dns.Options{
				Servers: []netip.AddrPort{server}, Timeout: 3 * time.Second,
				Summary: report.DNSSummary, Hooks: observe.Hooks{Exchange: report.Exchange},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := client.Close(ctx); err != nil {
					t.Error(err)
				}
			}()
			if _, err := client.Query(context.Background(), "mailgw.corp.example", dnsmessage.TypeA); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			text := output.String()
			if !verbose {
				if text != "" {
					t.Fatalf("successful DNS details escaped compact report:\n%s", text)
				}
				return
			}
			for _, want := range []string{`[OK] DNS: name="mailgw.corp.example." type=A duration=`,
				"winner=" + server.String() + " transport=udp servers_queried=1 outcome=answered purpose=application"} {
				if !strings.Contains(text, want) {
					t.Errorf("missing %q:\n%s", want, text)
				}
			}
			if strings.Count(text, "] DNS:") != 1 || strings.Contains(text, `protocol="dns"`) != verbose ||
				strings.Contains(text, "attempts=1") != verbose {
				t.Fatalf("incorrect SDK summary count/verbosity:\n%s", text)
			}
		})
	}
}
