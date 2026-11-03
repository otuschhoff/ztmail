package main

import (
	"bytes"
	"io"
	"net/mail"
	"reflect"
	"testing"
)

func TestMachinePrincipalRealmQualification(t *testing.T) {
	credentials, err := credentialOptions(options{
		auth: "keytab", keytab: "krb5.keytab", principal: "SNEU1-AL04$", realm: "EU.SOCIONEXT.COM",
	})
	if err != nil || credentials.Principal != "SNEU1-AL04$@EU.SOCIONEXT.COM" {
		t.Fatalf("principal=%q err=%v", credentials.Principal, err)
	}
}

func TestHostTestmailRecipientPolicy(t *testing.T) {
	for _, tt := range []struct {
		name            string
		recipients      []string
		canonical, from string
		hostWithoutMail bool
		want            []string
		fail            bool
	}{
		{"original-command", nil, "", "Oliver.Tuschhoff.SNEU-EXTERNAL@eu.socionext.com", true,
			[]string{"Oliver.Tuschhoff.SNEU-EXTERNAL@eu.socionext.com"}, false},
		{"saved-sender", nil, "", "saved@example.test", true, []string{"saved@example.test"}, false},
		{"explicit-recipient", []string{"recipient@example.test"}, "", "sender@example.test", true,
			[]string{"recipient@example.test"}, false},
		{"no-sender", nil, "", "", true, nil, true},
		{"recipient-but-no-sender", []string{"recipient@example.test"}, "", "", true, nil, true},
		{"null-sender", nil, "", "<>", true, nil, true},
		{"bad-sender", nil, "", "bad\n@example.test", true, nil, true},
		{"user-default", nil, "own@example.test", "other@example.test", false, []string{"own@example.test"}, false},
		{"host-with-mail", nil, "host@example.test", "other@example.test", false, []string{"host@example.test"}, false},
		{"user-missing-mail", nil, "", "other@example.test", false, nil, true},
		{"null-with-canonical", nil, "own@example.test", "<>", false, []string{"own@example.test"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := testmailRecipients(tt.recipients, tt.canonical, tt.from, "example.test", tt.hostWithoutMail)
			if (err != nil) != tt.fail || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("recipients=%v err=%v, want=%v failure=%t", got, err, tt.want, tt.fail)
			}
		})
	}
}

func TestHostTestmailGeneratedMessageUsesConfiguredSender(t *testing.T) {
	from := "Oliver.Tuschhoff.SNEU-EXTERNAL@eu.socionext.com"
	recipients, err := testmailRecipients(nil, "", from, "eu.socionext.com", true)
	if err != nil {
		t.Fatal(err)
	}
	report := newTestReport(io.Discard, false)
	report.Value("User", "SNEU1-AL04$@EU.SOCIONEXT.COM")
	report.Value("Mail (from)", from)
	report.Line("WARN", "Canonical AD mail lookup", "host directory account has no canonical mailbox")
	data, err := report.TestMessage(from, recipients)
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"From", "To"} {
		address, err := mail.ParseAddress(message.Header.Get(key))
		if err != nil || address.Address != from {
			t.Fatalf("%s=%q err=%v", key, message.Header.Get(key), err)
		}
	}
}
