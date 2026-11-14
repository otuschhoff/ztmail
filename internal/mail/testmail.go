package mail

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
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
	done := r.Measure("Report preparation")
	defer done()
	if err := r.OutputError(); err != nil {
		return nil, err
	}
	r.renderMu.Lock()
	defer r.renderMu.Unlock()
	copyReport, sender, to, err := r.testMessageSnapshot(from, recipients)
	if err != nil {
		return nil, err
	}
	snapshotAt := copyReport.snapshotAt
	tables := copyReport.reportTables()
	jsonData, err := copyReport.jsonSnapshotTables(tables)
	if err != nil {
		return nil, err
	}
	var message bytes.Buffer
	multipartWriter := multipart.NewWriter(&message)
	alternativeBoundary := rand.Text()
	subject := "ztmail diagnostic test"
	if copyReport.debug {
		subject += " (debug)"
	}
	fmt.Fprintf(&message, "Date: %s\r\nMessage-ID: <%s@ztmail.invalid>\r\nFrom: %s\r\nTo: %s\r\n"+
		"Subject: %s\r\nMIME-Version: 1.0\r\n"+
		"Content-Type: multipart/mixed; boundary=%q\r\n\r\n",
		snapshotAt.Format(time.RFC1123Z), rand.Text(), sender, strings.Join(to, ", "), subject, multipartWriter.Boundary())
	bodyPart, err := multipartWriter.CreatePart(textproto.MIMEHeader{
		"Content-Type": {fmt.Sprintf("multipart/alternative; boundary=%q", alternativeBoundary)},
	})
	if err != nil {
		return nil, fmt.Errorf("create testmail body: %w", err)
	}
	alternativeWriter := multipart.NewWriter(bodyPart)
	if err := alternativeWriter.SetBoundary(alternativeBoundary); err != nil {
		return nil, fmt.Errorf("set testmail alternative boundary: %w", err)
	}
	for _, format := range []reportFormat{reportPlain, reportHTML} {
		contentType := "text/plain; charset=UTF-8"
		if format == reportHTML {
			contentType = "text/html; charset=UTF-8"
		}
		part, err := alternativeWriter.CreatePart(textproto.MIMEHeader{
			"Content-Type": {contentType}, "Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, fmt.Errorf("create testmail part: %w", err)
		}
		prelude := reportNote(format, "ztmail diagnostic test message") + "\n\n" +
			reportNote(format, "Snapshot taken after transport authentication, before sending this message (before DATA); TLS-only mode has no SMTP AUTH confirmation.") + "\n" +
			reportNote(format, "DATA acceptance, QUIT and final cleanup are not included; consult the local report.") + "\n" +
			reportNote(format, "This message contains account names and internal topology. Review before sharing.") + "\n\n"
		prefix, suffix := "", ""
		if format == reportHTML {
			prefix = `<!doctype html><html><head><meta charset="utf-8"><title>ztmail diagnostic test</title></head>` +
				`<body style="font-family:Arial,sans-serif;color:#111827;background:#ffffff;line-height:1.5">`
			suffix = "</body></html>"
		}
		writer := quotedprintable.NewWriter(part)
		for _, chunk := range []string{prefix, prelude, copyReport.renderTables(format, tables), "\n", suffix} {
			if _, err := io.WriteString(writer, chunk); err != nil {
				return nil, fmt.Errorf("encode testmail part: %w", err)
			}
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("finish testmail part: %w", err)
		}
	}
	if err := alternativeWriter.Close(); err != nil {
		return nil, fmt.Errorf("finish testmail alternatives: %w", err)
	}
	attachment, err := multipartWriter.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"application/json; charset=UTF-8; name=ztmail-report.json"},
		"Content-Disposition":       {"attachment; filename=ztmail-report.json"},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, fmt.Errorf("create testmail JSON attachment: %w", err)
	}
	writer := quotedprintable.NewWriter(attachment)
	if _, err := writer.Write(jsonData); err != nil {
		return nil, fmt.Errorf("encode testmail JSON attachment: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish testmail JSON attachment: %w", err)
	}
	if err := multipartWriter.Close(); err != nil {
		return nil, fmt.Errorf("finish testmail: %w", err)
	}
	if err := r.OutputError(); err != nil {
		return nil, err
	}
	return message.Bytes(), nil
}

func (r *TestReport) testMessageSnapshot(from string, recipients []string) (*TestReport, string, []string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.outputErr != nil {
		return nil, "", nil, r.outputErr
	}
	if from == "" {
		from = r.values["Canonical mail"]
	}
	sender, err := mail.ParseAddress(from)
	if err != nil {
		return nil, "", nil, fmt.Errorf("testmail From: %w", err)
	}
	if len(recipients) == 0 {
		return nil, "", nil, errors.New("testmail requires a recipient")
	}
	to := make([]string, 0, len(recipients))
	for _, recipient := range recipients {
		address, err := mail.ParseAddress(recipient)
		if err != nil {
			return nil, "", nil, fmt.Errorf("testmail To: %w", err)
		}
		to = append(to, address.String())
	}
	return r.snapshotLocked(time.Now()), sender.String(), to, nil
}
