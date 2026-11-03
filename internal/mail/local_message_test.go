package mail

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestPrepareLocalMessagePreservesSenderAndBlindRecipients(t *testing.T) {
	message := "From: original@example.com\r\nSender: original@example.com\r\nTo: to@example.com\r\nBcc: blind@example.com,\r\n other@example.com\r\nSubject: test\r\n\r\nbody\r\n.\r\n"
	data, recipients, err := PrepareLocalMessage(strings.NewReader(message), []string{"root", "root"}, true, true)
	want := []string{"root", "to@example.com", "blind@example.com", "other@example.com"}
	if err != nil || !reflect.DeepEqual(recipients, want) {
		t.Fatalf("recipients=%q, err=%v", recipients, err)
	}
	clean := strings.Replace(message, "Bcc: blind@example.com,\r\n other@example.com\r\n", "", 1)
	if !bytes.Equal(data, []byte(clean)) {
		t.Fatalf("unknown sender/body changed: %q", data)
	}
}

func TestPrepareLocalMessageRejectsUnsafeRecipientsAndMalformedInput(t *testing.T) {
	for _, recipient := range []string{"|/bin/sh", "/tmp/file", "|pipe@example.com", ":include:file", "a\nb", "bad address", ""} {
		if _, _, err := PrepareLocalMessage(strings.NewReader("Subject: test\n\nbody\n"), []string{recipient}, false, true); err == nil {
			t.Errorf("unsafe local recipient accepted: %q", recipient)
		}
	}
	if _, _, err := PrepareLocalMessage(strings.NewReader("Subject: test\nmissing separator\n"), []string{"root"}, false, true); err == nil {
		t.Fatal("malformed local message accepted")
	}
}
