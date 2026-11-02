package mail

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
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
	copyReport := &TestReport{values: r.values, started: r.started, rows: r.rows, debug: r.debug, verbose: r.verbose,
		traces: r.traces, traceEnds: r.traceEnds, inventory: r.inventory}
	var message bytes.Buffer
	multipartWriter := multipart.NewWriter(&message)
	subject := "ztmail diagnostic test"
	if r.debug {
		subject += " (debug)"
	}
	fmt.Fprintf(&message, "Date: %s\r\nMessage-ID: <%s@ztmail.invalid>\r\nFrom: %s\r\nTo: %s\r\n"+
		"Subject: %s\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: multipart/alternative; boundary=%q\r\n\r\n",
		time.Now().Format(time.RFC1123Z), rand.Text(), sender.String(), strings.Join(to, ", "), subject, multipartWriter.Boundary())
	for _, format := range []reportFormat{reportPlain, reportHTML} {
		contentType := "text/plain; charset=UTF-8"
		if format == reportHTML {
			contentType = "text/html; charset=UTF-8"
		}
		part, err := multipartWriter.CreatePart(textproto.MIMEHeader{
			"Content-Type": {contentType}, "Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, fmt.Errorf("create testmail part: %w", err)
		}
		body := reportNote(format, "ztmail diagnostic test message") + "\n\n" +
			reportNote(format, "Snapshot taken after SMTP authentication, before sending this message.") + "\n" +
			reportNote(format, "DATA acceptance, QUIT and final cleanup are not included; consult the local report.") + "\n" +
			reportNote(format, "This message contains account names and internal topology. Review before sharing.") + "\n\n" +
			copyReport.renderFormat(format) + "\n"
		if format == reportHTML {
			body = `<!doctype html><html><head><meta charset="utf-8"><title>ztmail diagnostic test</title></head>` +
				`<body style="font-family:Arial,sans-serif;color:#111827;background:#ffffff;line-height:1.5">` + body + "</body></html>"
		}
		writer := quotedprintable.NewWriter(part)
		if _, err := writer.Write([]byte(body)); err != nil {
			return nil, fmt.Errorf("encode testmail part: %w", err)
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("finish testmail part: %w", err)
		}
	}
	if err := multipartWriter.Close(); err != nil {
		return nil, fmt.Errorf("finish testmail: %w", err)
	}
	return message.Bytes(), nil
}
