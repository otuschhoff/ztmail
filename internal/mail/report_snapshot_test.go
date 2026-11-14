package mail

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/otuschhoff/adbind/ad/discovery"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/adbind/ad/observe"
)

func TestReportSnapshotOwnsAllRenderingState(t *testing.T) {
	report := testMessageBenchmarkFixture(10, true)
	report.color, report.testMail, report.passwordPrompted = true, true, true
	report.promptDuration = time.Millisecond
	report.tlsDetails = []table.Row{{"Subject", "original subject"}}
	report.tlsCrypto = []table.Row{{"Certificate key", "Ed25519", "~128bit"}}
	report.tlsValidity = []certificateValidity{{"certificate", fixtureEpoch, fixtureEpoch.Add(time.Hour)}}
	report.tlsStrength, report.tlsStrengthReason = 128, "original reason"
	report.authentication.ClientCertificate = &CertificateInfo{Subject: "original client", PublicKey: "Ed25519", ClassicalKeyStrength: 128}
	report.ticketMetadata.Service = kerberos.MetadataField[string]{Value: "smtp/original", Available: true}
	endpoint := discovery.Endpoint{FQDN: "dc.corp.example", Port: 389, Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	report.Inventory(discovery.InventoryEvent{Advertised: []discovery.Endpoint{endpoint},
		Current: discovery.ServiceInventory{Candidates: []discovery.Endpoint{endpoint}}, Retired: []discovery.Endpoint{endpoint}})
	report.mu.Lock()
	snapshot := report.snapshotLocked(fixtureEpoch.Add(time.Second))
	report.mu.Unlock()
	before, err := snapshot.jsonSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	rendered := make(map[reportFormat]string)
	for _, format := range []reportFormat{reportPlain, reportHTML, reportTerminal} {
		rendered[format] = snapshot.renderFormat(format)
	}
	if snapshot.authentication.ClientCertificate == report.authentication.ClientCertificate ||
		snapshot.output != nil || snapshot.outputActive != nil || snapshot.outputQueue != nil {
		t.Fatal("snapshot aliases certificate metadata or copied output machinery")
	}
	report.mu.Lock()
	report.values["User"] = "changed user"
	report.rows[0].detail = "changed issue"
	report.traces[0].Operation = "changed operation"
	report.traceEnds[0] = fixtureEpoch.Add(10 * time.Second)
	for i := range report.inventory {
		for _, group := range [][]discovery.Endpoint{report.inventory[i].Advertised, report.inventory[i].Current.Candidates, report.inventory[i].Retired} {
			for j := range group {
				group[j].FQDN = "changed.example"
				if len(group[j].Addresses) > 0 {
					group[j].Addresses[0] = netip.MustParseAddr("192.0.2.99")
				}
			}
		}
		report.inventory[i].Current.Generation++
	}
	report.tlsDetails[0][1] = "changed subject"
	report.tlsCrypto[0][1] = "changed key"
	report.tlsValidity[0].end = fixtureEpoch
	report.tlsStrength, report.tlsStrengthReason = 0, "changed reason"
	report.authentication.ClientCertificate.Subject = "changed client"
	report.authentication.ServerVerification.PolicyPassed = true
	report.ticketMetadata.Service.Value = "smtp/changed"
	report.promptDuration = time.Hour
	report.color, report.debug, report.verbose, report.testMail, report.passwordPrompted = false, false, false, false, false
	report.mu.Unlock()
	after, err := snapshot.jsonSnapshot()
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("source mutation changed snapshot JSON: %v", err)
	}
	for format, expected := range rendered {
		if got := snapshot.renderFormat(format); got != expected {
			t.Fatalf("source mutation changed format %v", format)
		}
	}
	snapshot.values["User"] = "snapshot-only user"
	snapshot.rows[0].detail = "snapshot-only issue"
	snapshot.inventory[1].Advertised[0].Addresses[0] = netip.MustParseAddr("192.0.2.42")
	snapshot.tlsDetails[0][1] = "snapshot-only subject"
	snapshot.authentication.ClientCertificate.Subject = "snapshot-only client"
	if report.values["User"] != "changed user" || report.rows[0].detail != "changed issue" ||
		report.inventory[1].Advertised[0].Addresses[0].String() != "192.0.2.99" ||
		report.tlsDetails[0][1] != "changed subject" || report.authentication.ClientCertificate.Subject != "changed client" {
		t.Fatal("snapshot mutation changed live report state")
	}
}

type snapshotRenderGate struct {
	entered, resume chan struct{}
	first, release  sync.Once
}

func (g *snapshotRenderGate) String() string {
	g.first.Do(func() {
		close(g.entered)
		<-g.resume
	})
	return "TLS off"
}

func (g *snapshotRenderGate) unblock() {
	g.release.Do(func() { close(g.resume) })
}

func TestReportObserversProgressAfterSnapshotCapture(t *testing.T) {
	for _, final := range []bool{false, true} {
		t.Run(map[bool]string{false: "testmail", true: "terminal"}[final], func(t *testing.T) {
			report := testMessageBenchmarkFixture(10, true)
			gate := &snapshotRenderGate{entered: make(chan struct{}), resume: make(chan struct{})}
			report.tlsDetails = []table.Row{{"Status", gate}}
			var workers sync.WaitGroup
			t.Cleanup(func() { gate.unblock(); workers.Wait() })
			type result struct {
				data []byte
				err  error
			}
			rendered := make(chan result, 1)
			workers.Go(func() {
				var data []byte
				var err error
				if final {
					var output bytes.Buffer
					report.output = &output
					report.Finish(&err)
					data = output.Bytes()
				} else {
					data, err = report.TestMessage("", []string{"recipient@corp.example"})
				}
				rendered <- result{data, err}
			})
			select {
			case <-gate.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("renderer did not reach captured-state gate")
			}
			updated := make(chan struct{})
			workers.Go(func() {
				report.Value("User", "after-capture user")
				report.Trace(context.Background(), observe.TraceEvent{Phase: observe.TraceCompleted, Operation: "after-capture trace"})
				report.Inventory(discovery.InventoryEvent{Advertised: []discovery.Endpoint{{FQDN: "after-capture.example", Port: 389}}})
				report.KerberosTicket(kerberos.TicketMetadata{Service: kerberos.MetadataField[string]{Value: "after-capture ticket", Available: true}})
				close(updated)
			})
			select {
			case <-updated:
			case <-time.After(time.Second):
				t.Fatal("observer updates blocked behind captured-state rendering")
			}
			gate.unblock()
			got := <-rendered
			workers.Wait()
			if got.err != nil || len(got.data) == 0 || bytes.Contains(got.data, []byte("after-capture")) {
				t.Fatalf("captured output changed or failed: bytes=%d error=%v", len(got.data), got.err)
			}
			if report.values["User"] != "after-capture user" || report.ticketMetadata.Service.Value != "after-capture ticket" {
				t.Fatal("live report lost concurrent observations")
			}
		})
	}
}

func TestTestMessageRetainsOutputFailureDuringRendering(t *testing.T) {
	report := testMessageBenchmarkFixture(10, true)
	writer := &callbackReportWriter{report: report, fail: true}
	report.output = writer
	gate := &snapshotRenderGate{entered: make(chan struct{}), resume: make(chan struct{})}
	report.tlsDetails = []table.Row{{"Status", gate}}
	var workers sync.WaitGroup
	t.Cleanup(func() { gate.unblock(); workers.Wait() })
	result := make(chan error, 1)
	workers.Go(func() {
		data, err := report.TestMessage("", []string{"recipient@corp.example"})
		if len(data) != 0 {
			result <- errors.New("failed required output returned usable testmail bytes")
		} else {
			result <- err
		}
	})
	select {
	case <-gate.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("renderer did not reach captured-state gate")
	}
	report.Line("WARN", "After capture", "required output fails")
	outputErr := report.OutputError()
	gate.unblock()
	err := <-result
	workers.Wait()
	if outputErr == nil || !errors.Is(err, outputErr) || !strings.Contains(err.Error(), "report output") {
		t.Fatalf("rendering output failure=%v; retained=%v", err, outputErr)
	}
	if report.values["Writer callback"] != "recorded" || report.values["Error callback"] != "recorded" {
		t.Fatal("output failure callbacks could not update state")
	}
}
