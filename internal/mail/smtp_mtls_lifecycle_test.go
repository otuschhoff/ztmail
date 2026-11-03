package mail

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestCertificateExternalCancellationAndFreshEvidence(t *testing.T) {
	fixture := newCertificateSMTPFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	releasePeer := sync.OnceFunc(func() { close(release) })
	defer releasePeer()
	fixture.beforeAuth = func() { close(started); <-release }
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	wire := make(chan smtpResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			wire <- smtpResult{err: err}
			return
		}
		wire <- serveCertificateSMTP(conn, fixture, true, true, false)
	}()
	resolver := certificateResolver{netip.MustParseAddr("127.0.0.1")}
	var auth AuthenticationResult
	config := Config{Relay: "relay.example.test", Hello: "host.example.test", TLSMode: "implicit",
		Port: listener.Addr().(*net.TCPAddr).Port, Timeout: 3 * time.Second, Auth: AuthMTLSExternal,
		ClientCertificate: fixture.client, ServerTrust: ServerTrust{Mode: RootsReplace, Certificates: [][]byte{fixture.ca.Raw}},
		From: "sender@example.test", Authentication: func(result AuthenticationResult) { auth = result }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- Deliver(ctx, config, []string{"recipient@example.test"}, []byte("Subject: Test\r\n\r\nBody\r\n"), resolver, io.Discard)
	}()
	select {
	case <-started:
	case err := <-finished:
		t.Fatalf("operation did not reach EXTERNAL: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("EXTERNAL phase not reached")
	}
	cancel()
	select {
	case err := <-finished:
		if err == nil || errors.Is(err, ErrDeliveryUncertain) || auth.SMTPAuthConfirmed ||
			!auth.TLSEstablished || !auth.ClientCertificatePresented {
			t.Fatalf("cancelled EXTERNAL lost certain failure/evidence: %+v %v", auth, err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt blocked EXTERNAL")
	}
	releasePeer()
	assertNoEmailCommands(t, <-wire)
	fixture.beforeAuth = nil
	listener2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener2.Close()
	fixture.server = fixture.server.Clone()
	fixture.server.ClientAuth = 0
	wire2 := make(chan smtpResult, 1)
	go func() {
		conn, err := listener2.Accept()
		if err != nil {
			wire2 <- smtpResult{err: err}
			return
		}
		wire2 <- serveCertificateSMTP(conn, fixture, true, true, false)
	}()
	config.Port = listener2.Addr().(*net.TCPAddr).Port
	if err := Deliver(context.Background(), config, nil, nil, resolver, io.Discard); err == nil {
		t.Fatal("second operation without CertificateRequest succeeded")
	}
	if auth.ClientCertificatePresented || auth.ClientCertificateRequested || auth.SMTPAuthConfirmed {
		t.Fatalf("connection evidence carried over: %+v", auth)
	}
	assertNoEmailCommands(t, <-wire2)
}
