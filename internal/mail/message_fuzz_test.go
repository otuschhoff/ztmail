package mail

import (
	"bytes"
	"io"
	stdmail "net/mail"
	"slices"
	"strings"
	"testing"
)

func FuzzMessagePreparation(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("Subject: test\r\n\r\nbody\r\n.\r\n"),
		[]byte("To: \"a b\"@corp.example\nBcc: hidden@corp.example,\n\tsecond@corp.example\n\nbody\n"),
		[]byte("Resent-To: user@corp.example\nResent-Bcc: hidden@corp.example\n\t(comment)\nSubject: test\n\n\x00\xff.\n"),
		[]byte("Bcc : hidden@corp.example\n\nbody\n"),
		[]byte("Bad\x01: value\n\nbody\n"),
		[]byte("Subject: <script>&\"'\r\n\r\n\x00\xff\r\n.\r\n"),
		{},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		original := bytes.Clone(data)
		args := []string{"explicit@corp.example"}
		clean, recipients, err := PrepareMessageBytes(data, args, "corp.example", true)
		if !bytes.Equal(data, original) || !slices.Equal(args, []string{"explicit@corp.example"}) {
			t.Fatal("preparation mutated borrowed input")
		}
		stream, streamedRecipients, streamErr := PrepareMessage(bytes.NewReader(data), args, "corp.example", true, true)
		if (err == nil) != (streamErr == nil) || !bytes.Equal(clean, stream) || !slices.Equal(recipients, streamedRecipients) {
			t.Fatalf("reader/byte behavior diverged: byte=%v reader=%v", err, streamErr)
		}
		if err != nil {
			if clean != nil || recipients != nil {
				t.Fatal("invalid message returned success-shaped data")
			}
			return
		}
		source, err := stdmail.ReadMessage(bytes.NewReader(original))
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := stdmail.ReadMessage(bytes.NewReader(clean))
		if err != nil {
			t.Fatalf("prepared message is not parseable: %v", err)
		}
		beforeBody, err := io.ReadAll(source.Body)
		if err != nil {
			t.Fatal(err)
		}
		afterBody, err := io.ReadAll(prepared.Body)
		if err != nil || !bytes.Equal(beforeBody, afterBody) {
			t.Fatalf("body changed: %v", err)
		}
		for name := range prepared.Header {
			if strings.EqualFold(name, "Bcc") || strings.EqualFold(name, "Resent-Bcc") {
				t.Fatal("blind recipient header survived preparation")
			}
		}
		again, _, err := PrepareMessageBytes(clean, recipients, "corp.example", false)
		if err != nil || !bytes.Equal(again, clean) {
			t.Fatalf("prepared message is not idempotent: %v", err)
		}
		owned := bytes.Clone(clean)
		if len(data) > 0 {
			data[0] ^= 1
		}
		if !bytes.Equal(clean, owned) {
			t.Fatal("prepared bytes alias borrowed input")
		}
	})
}

func FuzzEnvelopeAddressRoundTrip(f *testing.F) {
	for _, seed := range []string{"user", "user@corp.example", `"a b"@corp.example`, `"a\"b"@corp.example`,
		`Name <"a\\b"@corp.example>`, "<>", "a@corp.example\nBcc: b@corp.example", "a,b@corp.example", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		address, err := EnvelopeAddress(value, "corp.example", true)
		if err != nil {
			if address != "" {
				t.Fatal("invalid address returned a usable mailbox")
			}
			return
		}
		if address == "" {
			if value != "<>" {
				t.Fatal("non-null input became a null envelope")
			}
			return
		}
		if strings.ContainsAny(address, "\r\n\x00<>") {
			t.Fatal("forbidden envelope bytes survived normalization")
		}
		again, err := EnvelopeAddress(address, "corp.example", false)
		if err != nil || again != address {
			t.Fatalf("normalized mailbox did not round trip: %q %v", again, err)
		}
		bare, err := bareMailboxSpec(address)
		if err != nil || bare != address {
			t.Fatalf("normalized mailbox is not bare syntax: %q %v", bare, err)
		}
	})
}
