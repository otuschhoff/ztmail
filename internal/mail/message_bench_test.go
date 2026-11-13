package mail

import (
	"bytes"
	"fmt"
	"io"
	netmail "net/mail"
	"reflect"
	"strings"
	"testing"
)

type messageBenchCase struct {
	name                          string
	size, foldedBytes, recipients int
}

func messageBenchCases() []messageBenchCase {
	cases := []messageBenchCase{
		{"Bytes/1KiB", 1 << 10, 0, 1},
		{"Bytes/1MiB", 1 << 20, 0, 1},
		{"Bytes/10MiB", 10 << 20, 0, 1},
	}
	for _, n := range []int{1, 2, 4, 8, 16} {
		cases = append(cases, messageBenchCase{fmt.Sprintf("Folded/%dKiB", n), 0, n << 10, 1})
	}
	for _, n := range []int{1, 10, 100, 1000} {
		cases = append(cases, messageBenchCase{fmt.Sprintf("Recipients/%d", n), 0, 0, n})
	}
	return cases
}

func messageBenchFixture(tb testing.TB, c messageBenchCase) ([]byte, []byte, []string) {
	tb.Helper()
	var header strings.Builder
	header.WriteString("From: Original\r\n\t<original@example.test>\r\nSender: old@example.test\r\nTo: ")
	recipients := []string{"local@example.test"}
	for i := 0; i < c.recipients; i++ {
		if i > 0 {
			header.WriteString(",\r\n\t")
		}
		address := fmt.Sprintf("recipient%d@example.test", i)
		header.WriteString(address)
		recipients = append(recipients, address)
	}
	header.WriteString("\r\nSubject: synthetic measurement\r\n")
	if c.foldedBytes > 0 {
		header.WriteString("X-Folded: start\r\n")
		for n := 0; n < c.foldedBytes; n += 64 {
			header.WriteString("\t" + strings.Repeat("h", 64) + "\r\n")
		}
	}
	const blind = "Bcc: blind@example.test,\r\n\tother-blind@example.test\r\n"
	recipients = append(recipients, "blind@example.test", "other-blind@example.test")
	header.WriteString(blind + "\r\n")
	bodySize := 512
	if c.size > 0 {
		bodySize = c.size - header.Len()
	}
	if bodySize < 2 {
		tb.Fatal("fixture size cannot contain headers and body")
	}
	line := strings.Repeat("x", 74) + "\r\n"
	body := strings.Repeat(line, bodySize/len(line))
	if tail := bodySize % len(line); tail > 0 {
		body += strings.Repeat("y", tail)
	}
	raw := []byte(header.String() + body)
	clean := []byte(strings.Replace(header.String(), blind, "", 1) + body)
	return raw, clean, recipients
}

func BenchmarkPrepareMessage(b *testing.B) {
	for _, c := range messageBenchCases() {
		b.Run(c.name, func(b *testing.B) {
			raw, clean, recipients := messageBenchFixture(b, c)
			args := []string{"local", "local"}
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			for b.Loop() {
				out, envelope, err := PrepareMessage(bytes.NewReader(raw), args, "example.test", true, true)
				if err != nil || len(out) != len(clean) || len(envelope) != len(recipients) {
					b.Fatalf("prepare: bytes=%d recipients=%d err=%v", len(out), len(envelope), err)
				}
			}
		})
	}
}

func BenchmarkPrepareLocalMessage(b *testing.B) {
	for _, c := range messageBenchCases() {
		b.Run(c.name, func(b *testing.B) {
			raw, clean, recipients := messageBenchFixture(b, c)
			args := []string{"local", "local"}
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			for b.Loop() {
				out, envelope, err := PrepareLocalMessage(bytes.NewReader(raw), args, true, true)
				if err != nil || len(out) != len(clean) || len(envelope) != len(recipients) || envelope[0] != "local" {
					b.Fatalf("local prepare: bytes=%d recipients=%d err=%v", len(out), len(envelope), err)
				}
			}
		})
	}
}

func BenchmarkApplySender(b *testing.B) {
	for _, c := range messageBenchCases() {
		b.Run(c.name, func(b *testing.B) {
			_, input, _ := messageBenchFixture(b, c)
			snapshot := bytes.Clone(input)
			expected, sender, err := ApplySender(input, "", "selected@example.test", "example.test")
			if err != nil {
				b.Fatal(err)
			}
			checkMessageBenchBody(b, input, expected)
			b.ReportAllocs()
			b.SetBytes(int64(len(input)))
			for b.Loop() {
				out, envelope, err := ApplySender(input, "", "selected@example.test", "example.test")
				if err != nil || envelope != sender || len(out) != len(expected) {
					b.Fatalf("sender: bytes=%d envelope=%q err=%v", len(out), envelope, err)
				}
			}
			if !bytes.Equal(input, snapshot) {
				b.Fatal("sender rewrite mutated input")
			}
		})
	}
}

func checkMessageBenchBody(tb testing.TB, input, output []byte) {
	tb.Helper()
	body := func(data []byte) []byte {
		message, err := netmail.ReadMessage(bytes.NewReader(data))
		if err != nil {
			tb.Fatal(err)
		}
		raw, err := io.ReadAll(message.Body)
		if err != nil {
			tb.Fatal(err)
		}
		return raw
	}
	if !bytes.Equal(body(input), body(output)) {
		tb.Fatal("message body changed")
	}
}

func TestBenchmarkMessageFixtures(t *testing.T) {
	for _, c := range messageBenchCases() {
		t.Run(c.name, func(t *testing.T) {
			raw, clean, want := messageBenchFixture(t, c)
			snapshot := bytes.Clone(raw)
			args := []string{"local", "local"}
			for _, line := range bytes.Split(raw, []byte("\r\n")) {
				if len(line) > 998 {
					t.Fatal("fixture exceeds SMTP line limit")
				}
			}
			if c.size > 0 && len(raw) != c.size {
				t.Fatalf("fixture bytes=%d; want %d", len(raw), c.size)
			}
			out, recipients, err := PrepareMessage(bytes.NewReader(raw), args, "example.test", true, true)
			if err != nil || !bytes.Equal(out, clean) || !reflect.DeepEqual(recipients, want) {
				t.Fatalf("message/privacy/envelope mismatch: %v", err)
			}
			checkMessageBenchBody(t, raw, out)
			local, localRecipients, err := PrepareLocalMessage(bytes.NewReader(raw), args, true, true)
			localWant := append([]string(nil), want...)
			localWant[0] = "local"
			if err != nil || !bytes.Equal(local, clean) || !reflect.DeepEqual(localRecipients, localWant) {
				t.Fatalf("local message/envelope mismatch: %v", err)
			}
			rewritten, envelope, err := ApplySender(out, "", "selected@example.test", "example.test")
			if err != nil || envelope != "selected@example.test" {
				t.Fatalf("sender rewrite: %v", err)
			}
			checkMessageBenchBody(t, out, rewritten)
			parsed, err := netmail.ReadMessage(bytes.NewReader(rewritten))
			if err != nil {
				t.Fatal(err)
			}
			from, fromErr := netmail.ParseAddress(parsed.Header.Get("From"))
			sender, senderErr := netmail.ParseAddress(parsed.Header.Get("Sender"))
			if fromErr != nil || senderErr != nil || from.Address != envelope ||
				sender.Address != envelope || parsed.Header.Get("Bcc") != "" {
				t.Fatalf("rewritten headers: %v", err)
			}
			if !bytes.Equal(raw, snapshot) || !bytes.Equal(out, clean) || !reflect.DeepEqual(args, []string{"local", "local"}) {
				t.Fatal("operation mutated input")
			}
		})
	}
}
