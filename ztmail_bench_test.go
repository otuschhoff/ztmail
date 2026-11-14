package ztmail

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"
)

var benchmarkRelayFailure = errors.New("offline benchmark stops before relay I/O")

type preparationBenchmarkSession struct {
	*fakeSession
	ready  chan<- struct{}
	resume <-chan struct{}
}

func (s preparationBenchmarkSession) Resolve(ctx context.Context, _ string) ([]netip.Addr, error) {
	if s.ready != nil {
		select {
		case s.ready <- struct{}{}:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		select {
		case <-s.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, benchmarkRelayFailure
}

func libraryBenchmarkMessage(size int) Message {
	header := []byte("Subject: offline measurement\r\nBcc: blind@corp.example\r\n\r\n")
	data := make([]byte, size)
	copy(data, header)
	for i := len(header); i < len(data); i++ {
		switch (i - len(header)) % 76 {
		case 74:
			data[i] = '\r'
		case 75:
			data[i] = '\n'
		default:
			data[i] = 'x'
		}
	}
	return Message{Data: data, From: "sender@corp.example", Recipients: []string{"recipient@corp.example"}}
}

func libraryBenchmarkClient(b *testing.B, s preparationBenchmarkSession) *Client {
	b.Helper()
	c, err := New(Options{AD: testAD(b), Domain: "corp.example", TLS: TLSOff, Timeout: time.Minute})
	if err != nil {
		b.Fatal(err)
	}
	c.acquire = func(context.Context) (session, error) { return s, nil }
	return c
}

func checkLibraryBenchmarkResult(b *testing.B, result Result, err error) {
	b.Helper()
	if !errors.Is(err, benchmarkRelayFailure) || result.Accepted || result.From != "sender@corp.example" ||
		len(result.Recipients) != 1 || result.Recipients[0] != "recipient@corp.example" {
		b.Fatalf("preparation/ownership benchmark reached unexpected outcome: %+v %v", result, err)
	}
}

func BenchmarkLibraryPreparation(b *testing.B) {
	for _, size := range []int{1 << 10, 1 << 20, 10 << 20} {
		b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
			s := preparationBenchmarkSession{fakeSession: newSession()}
			c, message := libraryBenchmarkClient(b, s), libraryBenchmarkMessage(size)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for b.Loop() {
				result, err := c.Send(b.Context(), message)
				checkLibraryBenchmarkResult(b, result, err)
			}
		})
	}
}

func BenchmarkConcurrentLibraryPreparation(b *testing.B) {
	for _, size := range []int{1 << 20, 10 << 20} {
		b.Run(fmt.Sprintf("calls=4/bytes=%d", size), func(b *testing.B) {
			messages := make([]Message, 4)
			for i := range messages {
				messages[i] = libraryBenchmarkMessage(size)
			}
			s := preparationBenchmarkSession{fakeSession: newSession()}
			c := libraryBenchmarkClient(b, s)
			var retained uint64
			b.ReportAllocs()
			b.SetBytes(int64(4 * size))
			for b.Loop() {
				b.StopTimer()
				runtime.GC()
				var before runtime.MemStats
				runtime.ReadMemStats(&before)
				b.StartTimer()
				live := measureConcurrentPreparation(b, c, s, messages)
				if live > before.HeapAlloc && live-before.HeapAlloc > retained {
					retained = live - before.HeapAlloc
				}
			}
			b.ReportMetric(float64(retained), "retained-B/op")
		})
	}
}

func measureConcurrentPreparation(b *testing.B, c *Client, s preparationBenchmarkSession, messages []Message) uint64 {
	b.Helper()
	ctx, cancel := context.WithCancel(b.Context())
	ready, release := make(chan struct{}, len(messages)), make(chan struct{})
	s.ready, s.resume = ready, release
	c.acquire = func(context.Context) (session, error) { return s, nil }
	results := make(chan error, len(messages))
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	for _, message := range messages {
		workers.Go(func() {
			result, err := c.Send(ctx, message)
			if result.Accepted || result.From != "sender@corp.example" || len(result.Recipients) != 1 {
				err = errors.Join(err, errors.New("incorrect prepared envelope"))
			}
			results <- err
		})
	}
	for range messages {
		select {
		case <-ready:
		case err := <-results:
			b.Fatalf("call failed before the measurement barrier: %v", err)
		case <-ctx.Done():
			b.Fatal(ctx.Err())
		}
	}
	b.StopTimer()
	runtime.GC()
	var atBarrier runtime.MemStats
	runtime.ReadMemStats(&atBarrier)
	b.StartTimer()
	close(release)
	workers.Wait()
	for range messages {
		if err := <-results; !errors.Is(err, benchmarkRelayFailure) {
			b.Fatal(err)
		}
	}
	runtime.KeepAlive(messages)
	return atBarrier.HeapAlloc
}
