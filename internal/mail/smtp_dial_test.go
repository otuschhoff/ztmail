package mail

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"
)

type relayFixtureAddresses []netip.Addr

func (a relayFixtureAddresses) Resolve(context.Context, string) ([]netip.Addr, error) {
	return a, nil
}

func TestRelayStalledFirstStartsFallbackWithinOneSecond(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		addresses := relayFixtureAddresses{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
		client, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		started := time.Now()
		calls := 0
		var previous context.Context
		conn, err := dialRelayWithDialer(ctx, options{relay: "relay.example.test", port: 25}, addresses,
			func(ctx context.Context, network, target string) (net.Conn, error) {
				if previous != nil && previous.Err() == nil {
					t.Fatal("next attempt began before previous attempt context ended")
				}
				previous = ctx
				calls++
				if network != "tcp" || target != net.JoinHostPort(addresses[calls-1].String(), "25") {
					t.Fatalf("dial escaped admitted numeric endpoints: %s %s", network, target)
				}
				if calls == 1 {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				if elapsed := time.Since(started); elapsed > time.Second {
					t.Errorf("fallback started after %s; want at most one second", elapsed)
				}
				return client, nil
			})
		if err != nil || conn != client || calls != 2 || ctx.Err() != nil {
			t.Fatalf("fallback outcome: conn=%v err=%v calls=%d parent=%v", conn, err, calls, ctx.Err())
		}
		if previous.Err() == nil {
			t.Fatal("completed dial retained its attempt context")
		}
	})
}

func TestRelaySingleAndFinalAttemptsRetainDeadline(t *testing.T) {
	for _, count := range []int{1, 2, 5} {
		t.Run(fmt.Sprintf("addresses=%d", count), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
				defer cancel()
				addresses := make(relayFixtureAddresses, count)
				for i := range addresses {
					addresses[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
				}

				begin := time.Now()
				calls := 0
				conn, err := dialRelayWithDialer(ctx, options{port: 25}, addresses,
					func(ctx context.Context, _, _ string) (net.Conn, error) {
						calls++
						<-ctx.Done()
						return nil, ctx.Err()
					})
				if conn != nil || !errors.Is(err, ErrRelayUnavailable) || !errors.Is(err, context.DeadlineExceeded) ||
					time.Since(begin) != 4*time.Second || calls != count {
					t.Fatalf("total deadline or final attempt lost: conn=%v err=%v elapsed=%s calls=%d", conn, err, time.Since(begin), calls)
				}
			})
		})
	}
}

func TestRelayCancellationStopsFurtherAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cause := errors.New("first candidate failed")
	calls := 0
	addresses := relayFixtureAddresses{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	conn, err := dialRelayWithDialer(ctx, options{port: 25}, addresses,
		func(context.Context, string, string) (net.Conn, error) {
			calls++
			cancel()
			return nil, cause
		})
	if conn != nil || calls != 1 || !errors.Is(err, cause) || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled failover lost causes or started more work: conn=%v calls=%d err=%v", conn, calls, err)
	}
}

func TestRelayShortAndAbsentDeadlines(t *testing.T) {
	for _, budget := range []time.Duration{0, 200 * time.Millisecond} {
		t.Run(fmt.Sprintf("budget=%s", budget), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				if budget > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, budget)
					defer cancel()
				}
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				addresses := relayFixtureAddresses{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
				begin, calls := time.Now(), 0
				conn, err := dialRelayWithDialer(ctx, options{port: 25}, addresses,
					func(work context.Context, _, target string) (net.Conn, error) {
						calls++
						if target != net.JoinHostPort(addresses[calls-1].String(), "25") {
							t.Fatalf("unexpected numeric endpoint: %s", target)
						}
						if calls == 1 {
							<-work.Done()
							return nil, work.Err()
						}
						want := relayFallbackAttemptLimit
						if budget > 0 {
							want = budget / 2
						}
						if elapsed := time.Since(begin); elapsed != want {
							t.Fatalf("fallback started after %s, want %s", elapsed, want)
						}
						if budget == 0 {
							if _, ok := work.Deadline(); ok {
								t.Fatal("final address acquired an implicit deadline")
							}
						}
						return client, nil
					})
				if conn != client || err != nil || calls != 2 || ctx.Err() != nil {
					t.Fatalf("fallback: conn=%v err=%v calls=%d parent=%v", conn, err, calls, ctx.Err())
				}
			})
		})
	}
}

func TestRelayInvalidAddressAndPreCancellationDoNotDial(t *testing.T) {
	for _, input := range []string{"invalid", "0.0.0.0", "::", "224.0.0.1", "ff02::1", "canceled"} {
		t.Run(input, func(t *testing.T) {
			address, _ := netip.ParseAddr(input)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if input == "canceled" {
				address = netip.MustParseAddr("192.0.2.1")
				cancel()
			}
			conn, err := dialRelayWithDialer(ctx, options{port: 25}, relayFixtureAddresses{address},
				func(context.Context, string, string) (net.Conn, error) {
					t.Fatal("invalid or canceled attempt reached the dialer")
					return nil, nil
				})
			if conn != nil || err == nil {
				t.Fatalf("invalid/canceled attempt succeeded: conn=%v err=%v", conn, err)
			}
			if input == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation lost: %v", err)
			}
		})
	}
}

type relayCloseErrorConn struct {
	net.Conn
	err error
}

func (c relayCloseErrorConn) Close() error { return errors.Join(c.Conn.Close(), c.err) }

func TestRelayRequiredOutputClosesConnectionAndStopsAttempts(t *testing.T) {
	for _, connected := range []bool{false, true} {
		t.Run(fmt.Sprintf("connected=%t", connected), func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			cause := errors.New("TCP notification failed")
			dialCause := errors.New("connection refused")
			closeCause := errors.New("connection close failed")
			if connected {
				client = relayCloseErrorConn{Conn: client, err: closeCause}
			}
			report := NewTestReport(outputFailureWriter{match: "SMTP TCP connection", cause: cause}, true)
			addresses := relayFixtureAddresses{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
			calls := 0
			conn, err := dialRelayWithDialer(t.Context(), options{port: 25, report: report}, addresses,
				func(context.Context, string, string) (net.Conn, error) {
					calls++
					if connected {
						return client, nil
					}
					return nil, dialCause
				})
			if conn != nil || calls != 1 || !errors.Is(err, cause) || !errors.Is(err, ErrOutputFailed) {
				t.Fatalf("required notification allowed more work: conn=%v calls=%d err=%v", conn, calls, err)
			}
			if connected {
				if !errors.Is(err, closeCause) {
					t.Fatalf("rejected connection cleanup error was lost: %v", err)
				}
				if _, err := server.Read(make([]byte, 1)); err == nil {
					t.Fatal("rejected TCP connection remained open")
				}
			} else if !errors.Is(err, dialCause) {
				t.Fatalf("TCP and notification failure lost original dial cause: %v", err)
			}
		})
	}
}
