package mail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareMessage(t *testing.T) {
	input := "From: Sender <sender@example.com>\r\nTo: Alice <alice@example.com>\r\nCc: bob@example.com\r\nBcc: hidden@example.com,\r\n\tother@example.com\r\nSubject: original\r\n\r\nHello\r\n.\r\ntrailing\r\n"
	for _, ignore := range []bool{false, true} {
		t.Run(map[bool]string{false: "dot-terminates", true: "ignore-dots"}[ignore], func(t *testing.T) {
			data, recipients, err := PrepareMessage(strings.NewReader(input), []string{"alice@example.com", "local"}, "example.com", true, ignore)
			if err != nil {
				t.Fatal(err)
			}

			want := []string{"alice@example.com", "local@example.com", "bob@example.com", "hidden@example.com", "other@example.com"}
			if !reflect.DeepEqual(recipients, want) {
				t.Fatalf("recipients = %v; want %v", recipients, want)
			}
			removed := "Bcc: hidden@example.com,\r\n\tother@example.com\r\n"
			expected := strings.Replace(input, removed, "", 1)
			if !ignore {
				expected = strings.Split(expected, ".\r\n")[0]
			}
			if string(data) != expected {
				t.Fatalf("message = %q; want %q", data, expected)
			}
		})
	}
}

func TestAutomaticHeaderRecipientsAndSelfFallback(t *testing.T) {
	input := "To: to@example.com\nCc: cc@example.com\nBcc: blind@example.com\n\nbody\n"
	data, recipients, err := PrepareMessage(strings.NewReader(input), nil, "example.com", false, true)
	if err != nil || len(recipients) != 3 || strings.Contains(string(data), "Bcc:") {
		t.Fatalf("header fallback: recipients=%v err=%v data=%s", recipients, err, data)
	}
	_, recipients, err = PrepareMessage(strings.NewReader(input), []string{"arg@example.com"}, "example.com", false, true)
	if err != nil || len(recipients) != 1 || recipients[0] != "arg@example.com" {
		t.Fatalf("explicit recipient precedence: %v %v", recipients, err)
	}
	recipients, err = RecipientFallback(nil, "self@example.com", "example.com")
	if err != nil || len(recipients) != 1 || recipients[0] != "self@example.com" {
		t.Fatalf("self fallback: %v %v", recipients, err)
	}
	if _, err := RecipientFallback(nil, "", "example.com"); err == nil {
		t.Fatal("missing canonical self address must fail")
	}
}

func TestPrepareMessageResent(t *testing.T) {
	input := "Resent-Date: Thu, 1 Jan 2026 00:00:00 +0000\nResent-From: forwarder@example.com\nResent-To: new@example.com\nResent-Bcc: secret@example.com\nResent-Date: Wed, 31 Dec 2025 00:00:00 +0000\nResent-To: old@example.com\nTo: original@example.com\nBcc: original-secret@example.com\n\nbody\n"
	data, recipients, err := PrepareMessage(strings.NewReader(input), nil, "example.com", true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recipients, []string{"new@example.com", "secret@example.com"}) {
		t.Fatalf("unexpected resent recipients: %v", recipients)
	}
	if bytes.Contains(bytes.ToLower(data), []byte("bcc:")) {
		t.Fatalf("blind recipient header leaked: %s", data)
	}
}

func TestPrepareMessageNoHeaderRecipients(t *testing.T) {
	input := "To: not-an-address\nBcc: secret@example.com\n\nbody\n"
	data, recipients, err := PrepareMessage(strings.NewReader(input), []string{"recipient@example.com"}, "example.com", false, true)
	if err != nil || len(recipients) != 1 || bytes.Contains(data, []byte("Bcc:")) {
		t.Fatalf("data=%q recipients=%v err=%v", data, recipients, err)
	}
}

func TestResentFieldsNeedNotStartWithDate(t *testing.T) {
	input := "Resent-From: newest@example.com\nResent-To: new@example.com\nResent-Date: Thu, 1 Jan 2026 00:00:00 +0000\nResent-From: older@example.com\nResent-To: old@example.com\nResent-Date: Wed, 31 Dec 2025 00:00:00 +0000\nTo: original@example.com\n\nbody\n"
	_, recipients, err := PrepareMessage(strings.NewReader(input), nil, "example.com", true, true)
	if err != nil || !reflect.DeepEqual(recipients, []string{"new@example.com"}) {
		t.Fatalf("recipients=%v err=%v", recipients, err)
	}
}

func TestPrepareMessageFailures(t *testing.T) {
	tests := []struct {
		name, message string
		recipients    []string
		headers       bool
	}{
		{"empty", "", nil, true},
		{"no-separator", "Subject: test\n", []string{"user@example.com"}, false},
		{"bad-to", "To: bad <\n\nbody\n", nil, true},
		{"injection", "Subject: test\n\nbody\n", []string{"user@example.com\r\nRCPT TO:<bad@example.com>"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := PrepareMessage(strings.NewReader(tt.message), tt.recipients, "example.com", tt.headers, true); err == nil {
				t.Fatal("expected failure")
			}
		})
	}
}

func TestMissingHeaderBodyBlankLineExplainsRejection(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		input := strings.Join([]string{"Subject: test", "This is a testmail", ".", ""}, newline)
		_, _, err := PrepareMessage(strings.NewReader(input), []string{"recipient@example.com"}, "example.com", false, false)
		want := "invalid RFC 5322 message: line 2: expected a header before the blank line, but this line is not \"Name: value\"\n" +
			"Each header must use \"Name: value\". Insert a blank line between the last header and the body " +
			"(press Enter twice after the last header).\n" +
			"The message was rejected locally; nothing was sent to the mail gateway."
		if err == nil || err.Error() != want {
			t.Fatalf("error=%v; want %q", err, want)
		}
		if strings.Contains(err.Error(), "This is a testmail") {
			t.Fatal("error must not echo the message body")
		}
	}
}

func TestInteractiveMessageWithBlankLineIsAccepted(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n"} {
		input := strings.Join([]string{"Subject: test", "", "This is a testmail", ".", ""}, newline)
		message, recipients, err := PrepareMessage(strings.NewReader(input), []string{"recipient@example.com"}, "example.com", false, false)
		want := strings.Join([]string{"Subject: test", "", "This is a testmail", ""}, newline)
		if err != nil || string(message) != want || !reflect.DeepEqual(recipients, []string{"recipient@example.com"}) {
			t.Fatalf("message=%q recipients=%v err=%v", message, recipients, err)
		}
	}
}

func TestHeaderOnlyInputExplainsMissingBlankLine(t *testing.T) {
	for _, input := range []string{"Subject: test\n", "Subject: test"} {
		_, _, err := PrepareMessage(strings.NewReader(input), []string{"recipient@example.com"}, "example.com", false, true)
		if err == nil || !strings.Contains(err.Error(), "missing blank line") || !strings.Contains(err.Error(), "press Enter twice") {
			t.Fatalf("error=%v", err)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("input failed") }

func TestPrepareMessageReadFailure(t *testing.T) {
	if _, _, err := PrepareMessage(failingReader{}, nil, "example.com", true, true); err == nil || !strings.Contains(err.Error(), "input failed") {
		t.Fatalf("expected input error; got %v", err)
	}
}

type messageEndReader struct {
	data []byte
	err  error
}

type emptyMessageReader struct {
	calls int
}

func (r *emptyMessageReader) Read([]byte) (int, error) {
	r.calls++
	return 0, nil
}

func TestPrepareMessageNoReaderProgress(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		reader := &emptyMessageReader{}
		if _, _, err := PrepareMessage(reader, nil, "example.test", false, ignore); !errors.Is(err, io.ErrNoProgress) || reader.calls != 100 {
			t.Fatalf("ignoreDots=%t calls=%d error=%v", ignore, reader.calls, err)
		}
	}
}

func (r *messageEndReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}

func TestPrepareMessageReaderBoundaries(t *testing.T) {
	header := "Subject: test\n\n"
	readErr := errors.New("message source failed")
	for _, tc := range []struct {
		name, body, want string
		end              error
		ignore           bool
		fail             bool
	}{
		{"EOF with bytes", "body", "body", io.EOF, true, false},
		{"EOF with dots", "body\n.\nafter", "body\n.\nafter", io.EOF, true, false},
		{"dot before error", "body\n.\nafter", "body\n", readErr, false, false},
		{"unterminated dot", "body\n.", "body\n", io.EOF, false, false},
		{"data with error", "body", "", readErr, true, true},
		{"interactive data with error", "body", "", readErr, false, true},
		{"fragment is not dot line", strings.Repeat("x", 8192-len(header)) + ".\nafter\n.\n", strings.Repeat("x", 8192-len(header)) + ".\nafter\n", io.EOF, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &messageEndReader{[]byte(header + tc.body), tc.end}
			data, _, err := PrepareMessage(reader, []string{"to@example.test"}, "example.test", false, tc.ignore)
			if tc.fail {
				if !errors.Is(err, readErr) || !strings.HasPrefix(err.Error(), "read message: ") || data != nil {
					t.Fatalf("data=%q error=%v", data, err)
				}
			} else if err != nil || string(data) != header+tc.want {
				t.Fatalf("data=%q error=%v", data, err)
			}
		})
	}
}

func TestPrepareMessageBytesMatchesReaderAndOwnsOutput(t *testing.T) {
	for _, input := range []string{
		"Subject: test\n\n\x00body\n.\nno final newline",
		"To: \"a b\"@example.test,\r\n\tsecond@example.test\r\nBcc: blind@example.test\r\n\t(comment)\r\n\r\nopaque\r\n",
		"Resent-To: newest@example.test\nResent-Bcc: hidden@example.test\nResent-To: older@example.test\nTo: original@example.test\n\nbody",
		"X-Folded: " + strings.Repeat("\n\tvalue", 512) + "\nTo: to@example.test\n\nbody",
		"",
		"\tOrphan\n\nbody",
		"Bcc : hidden@example.test\n\nbody",
		"To: invalid <\n\nbody",
		"Subject: no separator\n",
	} {
		for _, headers := range []bool{false, true} {
			raw := []byte(input)
			original := bytes.Clone(raw)
			args := []string{"explicit@example.test"}
			expected, recipients, expectedErr := PrepareMessage(bytes.NewReader(raw), args, "example.test", headers, true)
			got, gotRecipients, err := PrepareMessageBytes(raw, args, "example.test", headers)
			if fmt.Sprint(err) != fmt.Sprint(expectedErr) || !bytes.Equal(got, expected) || !reflect.DeepEqual(gotRecipients, recipients) {
				t.Fatalf("headers=%t input=%q output=%q recipients=%q error=%v; expected %q %q %v", headers, input, got, gotRecipients, err, expected, recipients, expectedErr)
			}
			if !bytes.Equal(raw, original) || args[0] != "explicit@example.test" {
				t.Fatal("preparation modified caller-owned input")
			}
			if err != nil {
				continue
			}
			got[0] ^= 1
			gotRecipients[0] = "changed@example.test"
			if !bytes.Equal(raw, original) || args[0] != "explicit@example.test" {
				t.Fatal("output aliases caller-owned input")
			}
			saved := bytes.Clone(got)
			for i := range raw {
				raw[i] ^= 1
			}
			if !bytes.Equal(got, saved) {
				t.Fatal("caller mutation changed prepared output")
			}
		}
	}
}

func TestEnvelopeAddress(t *testing.T) {
	for _, tt := range []struct {
		input, want string
		null        bool
		fail        bool
	}{
		{"local", "local@example.com", false, false},
		{"User <user@example.com>", "user@example.com", false, false},
		{"<>", "", true, false},
		{"<>", "", false, true},
		{"", "", false, true},
		{"a@example.com\nx", "", false, true},
	} {
		got, err := EnvelopeAddress(tt.input, "example.com", tt.null)
		if (err != nil) != tt.fail || got != tt.want {
			t.Errorf("%q: got %q, %v; want %q (fail=%v)", tt.input, got, err, tt.want, tt.fail)
		}
	}
}

func TestApplySender(t *testing.T) {
	body := "MIME-Version: 1.0\r\nFrom: Original\r\n\t<original@example.com>\r\nSender: old@example.com\r\nTo: recipient@example.com\r\nSubject: Unchanged\r\n\r\n\x00binary\nbody\r\n"
	for _, tt := range []struct {
		name, explicit, canonical, envelope string
		null, fail                          bool
	}{
		{"canonical", "", "primary@example.com", "primary@example.com", false, false},
		{"override", "override@example.com", "primary@example.com", "override@example.com", false, false},
		{"override-without-mail", "override@example.com", "", "override@example.com", false, false},
		{"local-override", "override", "primary@example.com", "override@example.com", false, false},
		{"null", "<>", "", "", true, false},
		{"no-mail", "", "", "", false, true},
		{"invalid", "bad\n@example.com", "", "", false, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, envelope, err := ApplySender([]byte(body), tt.explicit, tt.canonical, "example.com")
			if (err != nil) != tt.fail {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.fail {
				return
			}
			if envelope != tt.envelope {
				t.Fatalf("envelope=%q; want %q", envelope, tt.envelope)
			}
			if tt.null {
				if string(result) != body {
					t.Fatal("null sender must preserve original headers/body")
				}
				return
			}
			expected := "From: <" + tt.envelope + ">\r\nMIME-Version: 1.0\r\nSender: <" + tt.envelope + ">\r\nTo: recipient@example.com\r\nSubject: Unchanged\r\n\r\n\x00binary\nbody\r\n"
			if string(result) != expected {
				t.Fatalf("message=%q; want %q", result, expected)
			}
		})
	}
}

func TestRewriteSenderWithoutFrom(t *testing.T) {
	message := "Subject: test\n\nbody\n"
	got, err := RewriteSender([]byte(message), "primary@example.com")
	if err != nil || string(got) != "From: <primary@example.com>\n"+message {
		t.Fatalf("message=%q err=%v", got, err)
	}
}

func TestRewriteSenderRemovesDuplicateFoldedFields(t *testing.T) {
	message := "From: one@example.com\nFrom: two@example.com\nSender: three@example.com\n folded\nSender: four@example.com\n\nbody\n"
	got, err := RewriteSender([]byte(message), "primary@example.com")
	want := "From: <primary@example.com>\nSender: <primary@example.com>\n\nbody\n"
	if err != nil || string(got) != want {
		t.Fatalf("message=%q err=%v", got, err)
	}
}
