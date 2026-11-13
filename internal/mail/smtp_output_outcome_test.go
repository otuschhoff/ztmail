package mail

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestSMTPAcceptedCleanupOutputRetainsBothCauses(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	results := make(chan smtpResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- smtpResult{err: err}
			return
		}
		results <- serveSMTP(conn, false, false)
	}()
	writerCause := errors.New("cleanup warning output broken")
	cleanupCause := errors.New("GSSAPI cleanup failed")
	security := &fakeSecurity{offer: []byte{1, 0, 0, 0}, closeErr: cleanupCause}
	backend := &fakeBackend{security: security, address: netip.MustParseAddr("127.0.0.1")}
	o := options{relay: "relay.example.test", hello: "host.example.test", port: listener.Addr().(*net.TCPAddr).Port,
		from: "from@example.test", timeout: time.Second, tlsMode: "off"}
	err = deliver(context.Background(), o, []string{"to@example.test"}, []byte("Subject: test\r\n\r\nbody\r\n"), backend,
		outputFailureWriter{cause: writerCause})
	result := <-results
	if !errors.Is(err, ErrAcceptedOutput) || !errors.Is(err, writerCause) || !errors.Is(err, cleanupCause) ||
		errors.Is(err, ErrDeliveryUncertain) || result.message == "" || security.closed != 1 {
		t.Fatalf("known accepted cleanup/output failure: err=%v message=%q closes=%d", err, result.message, security.closed)
	}
}

func TestSMTPOutputFailurePreservesRealUncertainty(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	reached, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	peer := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			peer <- err
			return
		}
		peer <- cancellationSMTPPeer(conn, certificateSMTPFixture{}, "off", "DATA-response", reached, release)
	}()
	writerCause := errors.New("uncertain cleanup output broken")
	cleanupCause := errors.New("security close failed")
	writer := outputFailureWriter{match: "GSSAPI cleanup", cause: writerCause}
	backend := &fakeBackend{security: &fakeSecurity{offer: []byte{1, 0, 0, 0}, closeErr: cleanupCause},
		address: netip.MustParseAddr("127.0.0.1")}
	o := options{relay: "relay.example.test", hello: "host.example.test", port: listener.Addr().(*net.TCPAddr).Port,
		from: "from@example.test", timeout: time.Second, tlsMode: "off", report: NewTestReport(writer, true)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- deliver(ctx, o, []string{"to@example.test"}, []byte("Subject: test\r\n\r\nbody\r\n"), backend, writer)
	}()
	select {
	case <-reached:
		cancel()
	case err := <-finished:
		t.Fatalf("failed before DATA acceptance boundary: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("DATA acceptance boundary not reached")
	}
	select {
	case err = <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation failed to interrupt DATA")
	}
	if !errors.Is(err, ErrDeliveryUncertain) || !errors.Is(err, context.Canceled) || !errors.Is(err, writerCause) ||
		!errors.Is(err, cleanupCause) || errors.Is(err, ErrAcceptedOutput) {
		t.Fatalf("uncertainty/cancellation/cleanup/output causes not retained: %v", err)
	}
	// Release the owned peer before returning; do not abandon cleanup work.
	release <- struct{}{}
	if err := <-peer; err != nil {
		t.Fatal(err)
	}
}
