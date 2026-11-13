package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/ztmail/internal/mail"
)

func TestQuotedDefaultSenderRoundTripAndNativeWire(t *testing.T) {
	executable, argsPath, messagePath := fakeLocalSendmail(t)
	configPath := isolatedSenderConfig(t)
	for _, address := range []string{`"a b"@example.test`, `"a\"b"@example.test`, `"a\\b"@example.test`} {
		t.Run(address, func(t *testing.T) {
			if path, err := writeDefaultSender(address); err != nil || path != configPath {
				t.Fatalf("write default: path=%q err=%v", path, err)
			}
			stored, err := readDefaultSender()
			if err != nil || stored != address {
				t.Fatalf("read default=%q err=%v", stored, err)
			}
			o, err := applyDefaultSender(operationOptions{commandFlags: commandFlags{domain: "example.test"}})
			if err != nil || o.from != address {
				t.Fatalf("applied default=%q err=%v", o.from, err)
			}
			for _, headers := range []bool{false, true} {
				raw := []byte("To: " + address + "\r\nBcc: " + address + "\r\nSubject: test\r\n\r\n.\r\nbody\r\n")
				args := []string{address}
				if headers {
					args = nil
				}
				message, recipients, err := mail.PrepareLocalMessage(bytes.NewReader(raw), args, headers, true)
				if err != nil {
					t.Fatal(err)
				}
				message, from, err := applySender(message, o.from, "", o.domain)
				if err != nil || from != address {
					t.Fatalf("sender=%q err=%v", from, err)
				}
				if err := submitLocalSendmail(t.Context(), executable, from, recipients, message, io.Discard); err != nil {
					t.Fatal(err)
				}
				captured, err := os.ReadFile(argsPath)
				got := strings.Split(strings.TrimSuffix(string(captured), "\n"), "\n")
				if err != nil || !reflect.DeepEqual(got, []string{"-i", "-f", address, "--", address}) {
					t.Fatalf("native argv=%q err=%v", got, err)
				}
				body, err := os.ReadFile(messagePath)
				if err != nil || bytes.Contains(body, []byte("Bcc:")) || !bytes.HasSuffix(body, []byte(".\r\nbody\r\n")) ||
					!bytes.Contains(body, []byte("From: <"+address+">")) {
					t.Fatalf("native message=%q err=%v", body, err)
				}
			}
		})
	}
}

func TestCommandMalformedHeaderNeverReachesNativeFallback(t *testing.T) {
	executable, argsPath, _ := fakeLocalSendmail(t)
	isolatedSenderConfig(t)
	for _, name := range []string{"Bcc ", "Bcc\t", "Bad Name", "Bad\x00Name", "Bad\xffName"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command := newCommand()
			command.SetContext(ctx)
			command.SetArgs([]string{"--domain", "corp.example.com", "--hostname", "host.corp.example.com",
				"--cred-source", "ccache", "--ccache", t.TempDir() + "/missing-cache",
				"--sendmail-path", executable, "-i", "recipient@corp.example.com"})
			command.SetIn(strings.NewReader(name + ": blind@corp.example.com\r\n\tfolded\r\n\r\nbody\r\n"))
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			err := command.Execute()
			if err == nil || !strings.Contains(err.Error(), "invalid RFC 5322 message") {
				t.Fatalf("invalid message not rejected locally: %v", err)
			}
			if _, err := os.Stat(argsPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid header reached native MTA: %v", err)
			}
		})
	}
}
