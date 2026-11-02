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

	"github.com/otuschhoff/adbind/ad/dns"
	"github.com/otuschhoff/adbind/ad/observe"
	"golang.org/x/net/dns/dnsmessage"
)

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
			text := output.String()
			want := "[OK] DNS: name=\"_ldap._tcp.corp.example.\" type=SRV duration=42ms " +
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
			NewTestReport(&output, false).DNSSummary(event)
			text := output.String()
			for _, want := range []string{"[" + test.status + "] DNS:", "winner=none", "servers_queried=0",
				"outcome=" + string(test.outcome), "duration=42ms"} {
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
	NewTestReport(&output, false).DNSSummary(event)
	if !strings.Contains(output.String(), "winner=none") ||
		!strings.Contains(output.String(), "responders=[192.0.2.10:53/udp, [2001:db8::10]:5353/tcp]") {
		t.Fatalf("consensus was misattributed:\n%s", &output)
	}
	event.Winner = event.Responses[1]
	output.Reset()
	NewTestReport(&output, false).DNSSummary(event)
	if !strings.Contains(output.String(), "winner=[2001:db8::10]:5353 transport=tcp") {
		t.Fatalf("IPv6/TCP endpoint was not preserved:\n%s", &output)
	}
}

func TestDNSSummariesAreConcurrentAndQuestionAttributed(t *testing.T) {
	var output bytes.Buffer
	report := NewTestReport(&output, false)
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
			index, time.Duration(index+1)*time.Millisecond, index+1)
		if !strings.Contains(output.String(), want+"\n") {
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
