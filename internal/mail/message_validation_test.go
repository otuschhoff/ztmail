package mail

import (
	"bytes"
	"fmt"
	stdmail "net/mail"
	"reflect"
	"strings"
	"testing"
)

func TestQuotedMailboxSurfaces(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"space", `"a b"@example.test`, `"a b"@example.test`},
		{"quote", `"a\"b"@example.test`, `"a\"b"@example.test`},
		{"backslash", `"a\\b"@example.test`, `"a\\b"@example.test`},
		{"consecutive dots", `"a..b"@example.test`, `"a..b"@example.test`},
		{"leading dot", `".ab"@example.test`, `".ab"@example.test`},
		{"trailing dot", `"ab."@example.test`, `"ab."@example.test`},
		{"unnecessary quoting", `"alice"@example.test`, "alice@example.test"},
		{"quoted at", `"a@b"@example.test`, `"a@b"@example.test`},
		{"domain literal", `"a b"@[192.0.2.1]`, `"a b"@[192.0.2.1]`},
		{"existing UTF-8 local", "\u00e9@example.test", "\u00e9@example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, err := EnvelopeAddress(tc.input, "example.test", false)
			if err != nil || address != tc.want {
				t.Fatalf("address=%q err=%v; want %q", address, err, tc.want)
			}
			for _, local := range []bool{false, true} {
				for _, headers := range []bool{false, true} {
					t.Run(fmt.Sprintf("local=%t/headers=%t", local, headers), func(t *testing.T) {
						raw := []byte("To: " + tc.input + "\r\nBcc: " + tc.input + "\r\nSubject: test\r\n\r\n\x00opaque\n.\r\n")
						args := []string{tc.input}
						if headers {
							args = nil
						}
						var out []byte
						var recipients []string
						var err error
						if local {
							out, recipients, err = PrepareLocalMessage(bytes.NewReader(raw), args, headers, true)
						} else {
							out, recipients, err = PrepareMessage(bytes.NewReader(raw), args, "example.test", headers, true)
						}
						if err != nil || !reflect.DeepEqual(recipients, []string{tc.want}) {
							t.Fatalf("recipients=%q err=%v", recipients, err)
						}
						if bytes.Contains(out, []byte("Bcc:")) || !bytes.HasSuffix(out, []byte("\x00opaque\n.\r\n")) {
							t.Fatalf("privacy/body changed: %q", out)
						}
					})
				}
			}
			for _, explicit := range []bool{false, true} {
				raw := []byte("From: original@example.test\nSender: original@example.test\nSubject: test\n\n\x00body\n")
				original := bytes.Clone(raw)
				from, canonical := "", tc.input
				if explicit {
					from, canonical = tc.input, ""
				}
				out, envelope, err := ApplySender(raw, from, canonical, "example.test")
				if err != nil || envelope != tc.want {
					t.Fatalf("explicit=%t envelope=%q err=%v", explicit, envelope, err)
				}
				if !bytes.Equal(raw, original) || !bytes.HasSuffix(out, []byte("\x00body\n")) {
					t.Fatal("sender rewrite mutated input/body")
				}
				parsed, err := stdmail.ReadMessage(bytes.NewReader(out))
				if err != nil {
					t.Fatal(err)
				}
				for _, field := range []string{"From", "Sender"} {
					address, err := stdmail.ParseAddress(parsed.Header.Get(field))
					want, parseErr := stdmail.ParseAddress(tc.input)
					if err != nil || parseErr != nil || address.Address != want.Address {
						t.Fatalf("%s=%q err=%v", field, parsed.Header.Get(field), err)
					}
				}
			}
			if _, err := RewriteSender([]byte("Subject: test\n\nbody\n"), tc.input); err != nil {
				t.Fatalf("bare quoted sender rejected: %v", err)
			}
		})
	}
}

func TestHeaderFieldNameBytes(t *testing.T) {
	for b := 0; b < 256; b++ {
		if b == '\r' || b == '\n' || b == ':' {
			continue
		}
		t.Run(fmt.Sprintf("byte=%02x", b), func(t *testing.T) {
			name := "X" + string(byte(b)) + "Field"
			raw := []byte(name + ": value\r\nSubject: test\r\n\r\n\x00opaque\nbody\r\n")
			valid := b >= 33 && b <= 57 || b >= 59 && b <= 126
			out, _, err := PrepareMessage(bytes.NewReader(raw), []string{"recipient@example.test"}, "example.test", false, true)
			if valid {
				if err != nil || !bytes.Equal(out, raw) {
					t.Fatalf("valid ftext changed/rejected: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "invalid RFC 5322 message") {
				t.Fatalf("invalid ftext accepted or unclassified: %v", err)
			}
			_, err = RewriteSender(raw, "sender@example.test")
			if (err == nil) != valid {
				t.Fatalf("sender rewrite ftext validity=%t err=%v", valid, err)
			}
		})
	}
	for _, name := range []string{"Bad Header", "Bad\rHeader", "Bcc ", "Bcc\t", "Resent-Bcc ", ""} {
		t.Run(fmt.Sprintf("invalid=%q", name), func(t *testing.T) {
			for _, local := range []bool{false, true} {
				raw := name + ": hidden@example.test\r\n\tother@example.test\r\n\r\nbody\r\n"
				var err error
				if local {
					_, _, err = PrepareLocalMessage(strings.NewReader(raw), []string{"recipient@example.test"}, false, true)
				} else {
					_, _, err = PrepareMessage(strings.NewReader(raw), []string{"recipient@example.test"}, "example.test", false, true)
				}
				if err == nil {
					t.Fatalf("local=%t accepted disguised/invalid header", local)
				}
			}
		})
	}
}

func TestQuotedRecipientsUseLatestResentBlock(t *testing.T) {
	raw := []byte("Resent-Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n" +
		"ReSeNt-To: \"a b\"@example.test,\r\n\t\"a\\\"b\"@example.test\r\n" +
		"rEsEnT-bCc: \"a b\"@example.test\r\n\t(comment)\r\n" +
		"Resent-Date: Sun, 31 Dec 2023 00:00:00 +0000\r\n" +
		"Resent-To: old@example.test\r\nResent-Bcc: old-blind@example.test\r\n" +
		"To: original@example.test\r\nBcC: blind@example.test\r\n\t(comment)\r\n\r\n\x00body\r\n")
	out, recipients, err := PrepareMessage(bytes.NewReader(raw), nil, "example.test", true, true)
	want := []string{`"a b"@example.test`, `"a\"b"@example.test`}
	if err != nil || !reflect.DeepEqual(recipients, want) {
		t.Fatalf("recipients=%q err=%v", recipients, err)
	}
	if bytes.Contains(bytes.ToLower(out), []byte("bcc:")) || bytes.Contains(out, []byte("(comment)")) ||
		!bytes.HasSuffix(out, []byte("\x00body\r\n")) || !bytes.Contains(out, []byte("Resent-To: old@example.test\r\n")) {
		t.Fatalf("privacy/retained headers/body changed: %q", out)
	}
}

func TestRewriteSenderRejectsOrphanContinuation(t *testing.T) {
	if _, err := RewriteSender([]byte("\torphan\nSubject: test\n\nbody\n"), "sender@example.test"); err == nil {
		t.Fatal("orphan continuation accepted")
	}
}

func TestRewriteSenderRejectsNonBareMailbox(t *testing.T) {
	for _, input := range []string{"Alice <alice@example.test>", "<alice@example.test>", "alice@example.test (comment)", " alice@example.test"} {
		t.Run(input, func(t *testing.T) {
			if _, err := RewriteSender([]byte("Subject: test\n\nbody\n"), input); err == nil {
				t.Fatal("non-bare sender accepted")
			}
		})
	}
}
