package ztmail

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestLibraryWarningsDoNotImplyAcceptance(t *testing.T) {
	for _, method := range []AuthMode{AuthMTLS, AuthMTLSExternal} {
		for _, testOnly := range []bool{false, true} {
			name := string(method) + "/send"
			if testOnly {
				name = string(method) + "/test"
			}
			t.Run(name, func(t *testing.T) {
				client, err := New(Options{AD: testAD(t), Domain: "corp.example", Auth: method,
					ClientCertificate: libraryClientCertificate(t),
					ServerTrust:       ServerTrust{InsecureAllowUnverifiableIssuer: true}})
				if err != nil {
					t.Fatal(err)
				}
				resolveErr := errors.New("relay discovery failed after policy notice")
				resolver := &stoppingOutputResolver{err: resolveErr}
				client.resolver = resolver
				var result Result
				if testOnly {
					result, err = client.Test(t.Context(), &bytes.Buffer{})
				} else {
					result, err = client.Send(t.Context(), Message{From: "sender@corp.example",
						Recipients: []string{"recipient@corp.example"}, Data: []byte("Subject: test\r\n\r\nbody\r\n")})
				}
				if !errors.Is(err, resolveErr) || result.Accepted || resolver.calls != 1 {
					t.Fatalf("unexpected submission outcome: result=%+v err=%v resolves=%d", result, err, resolver.calls)
				}
				found := false
				for _, warning := range result.Warnings {
					found = found || strings.Contains(warning.Error(), "issuer")
				}
				if !found {
					t.Fatalf("pre-acceptance policy warning lost: result=%+v", result)
				}
			})
		}
	}
}

type stoppingOutputResolver struct {
	calls int
	err   error
}

func (r *stoppingOutputResolver) Resolve(context.Context, string) ([]netip.Addr, error) {
	r.calls++
	return nil, r.err
}

func TestLibraryConciseReportOutputFailurePreservesOutcome(t *testing.T) {
	for _, method := range []AuthMode{AuthGSSAPI, AuthMTLS, AuthMTLSExternal} {
		t.Run(string(method), func(t *testing.T) {
			s := newSession()
			client := testClient(t, s)
			if method != AuthGSSAPI {
				var err error
				client, err = New(Options{AD: testAD(t), Domain: "corp.example", Auth: method, ClientCertificate: libraryClientCertificate(t)})
				if err != nil {
					t.Fatal(err)
				}
			}
			unexpected := errors.New("unexpected downstream operation")
			acquired := 0
			client.acquire = func(context.Context) (session, error) {
				acquired++
				return nil, unexpected
			}
			resolver := &stoppingOutputResolver{err: unexpected}
			client.resolver = resolver
			writeErr := errors.New("initial diagnostic output unavailable")
			result, err := client.Test(t.Context(), brokenWriter{writeErr})
			wantAcquire, wantResolve := 0, 1
			if method == AuthGSSAPI {
				wantAcquire, wantResolve = 1, 0
			}
			if !errors.Is(err, writeErr) || !errors.Is(err, unexpected) || result.Accepted ||
				acquired != wantAcquire || resolver.calls != wantResolve || s.releases.Load() != 0 {
				t.Fatalf("concise final output changed/lost outcome: result=%+v err=%v acquired=%d resolved=%d",
					result, err, acquired, resolver.calls)
			}
		})
	}
}

type blockedLibraryOutput struct {
	entered, resume chan struct{}
	err             error
}

func (w blockedLibraryOutput) Write([]byte) (int, error) {
	close(w.entered)
	<-w.resume
	return 0, w.err
}

func TestLibraryBlockingWriterExceedsOperationDeadline(t *testing.T) {
	client := testClient(t, newSession())
	operationErr := errors.New("acquisition failed before final output")
	client.acquire = func(context.Context) (session, error) {
		return nil, operationErr
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		writeErr := errors.New("released blocking writer")
		writer := blockedLibraryOutput{make(chan struct{}), make(chan struct{}), writeErr}
		done := make(chan error, 1)
		go func() {
			_, err := client.Test(ctx, writer)
			done <- err
		}()
		<-writer.entered
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatal("operation deadline has not expired")
		}
		select {
		case err := <-done:
			t.Fatalf("arbitrary writer was abandoned: %v", err)
		default:
		}
		close(writer.resume)
		if err := <-done; !errors.Is(err, writeErr) || !errors.Is(err, operationErr) {
			t.Fatalf("writer failure lost after release: %v", err)
		}
	})
}

type delayedReleaseSession struct {
	*fakeSession
	entered, resume chan struct{}
}

func (s delayedReleaseSession) release() {
	close(s.entered)
	<-s.resume
	s.fakeSession.release()
}

func TestLibraryWaitsForSynchronousLeaseCleanupAfterDeadline(t *testing.T) {
	base := newSession()
	client := testClient(t, base)
	client.options.Timeout = 2 * time.Second
	synctest.Test(t, func(t *testing.T) {
		wrapped := delayedReleaseSession{base, make(chan struct{}), make(chan struct{})}
		base.ctxWork = func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
		client.acquire = func(context.Context) (session, error) { return wrapped, nil }
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := client.Send(ctx, Message{From: "sender@corp.example", Recipients: []string{"recipient@corp.example"},
				Data: []byte("Subject: test\r\n\r\nbody\r\n")})
			done <- err
		}()
		<-wrapped.entered
		parentErr := ctx.Err()
		select {
		case err := <-done:
			t.Errorf("lease cleanup was abandoned: %v", err)
		default:
		}
		close(wrapped.resume)
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) || base.releases.Load() != 1 || !errors.Is(parentErr, context.DeadlineExceeded) {
			t.Fatalf("cleanup/error contract: %v parent=%v releases=%d", err, parentErr, base.releases.Load())
		}
	})
}
