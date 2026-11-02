package mail

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"
)

func (r *TestReport) EnableTestMail() {
	if r != nil {
		r.testMail = true
	}
}

func (r *TestReport) TestMessage(from string, recipients []string) ([]byte, error) {
	if r == nil {
		return nil, errors.New("testmail report is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.outputErr != nil {
		return nil, r.outputErr
	}
	if from == "" {
		from = r.values["Canonical mail"]
	}
	sender, err := mail.ParseAddress(from)
	if err != nil {
		return nil, fmt.Errorf("testmail From: %w", err)
	}
	if len(recipients) == 0 {
		return nil, errors.New("testmail requires a recipient")
	}
	to := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		address, err := mail.ParseAddress(recipient)
		if err != nil {
			return nil, fmt.Errorf("testmail To: %w", err)
		}
		to = append(to, address.String())
	}
	copyReport := &TestReport{values: r.values, started: r.started, rows: r.rows, debug: r.debug,
		traces: r.traces, traceEnds: r.traceEnds, inventory: r.inventory}
	body := "ztmail diagnostic test message\r\n\r\n" +
		"Snapshot taken after SMTP authentication, before sending this message.\r\n" +
		"DATA acceptance, QUIT and final cleanup are not included; consult the local report.\r\n" +
		"This message contains account names and internal topology. Review before sharing.\r\n\r\n" +
		strings.TrimSuffix(copyReport.render(), "\nNo email sent.") + "\r\n"
	var message bytes.Buffer
	subject := "ztmail diagnostic test"
	if r.debug {
		subject += " (debug)"
	}
	fmt.Fprintf(&message, "Date: %s\r\nMessage-ID: <%s@ztmail.invalid>\r\nFrom: %s\r\nTo: %s\r\n"+
		"Subject: %s\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n",
		time.Now().Format(time.RFC1123Z), rand.Text(), sender.String(), strings.Join(to, ", "), subject)
	writer := quotedprintable.NewWriter(&message)
	if _, err := writer.Write([]byte(body)); err != nil {
		return nil, fmt.Errorf("encode testmail: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish testmail: %w", err)
	}
	return message.Bytes(), nil
}
