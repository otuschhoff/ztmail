package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"strings"
)

func envelopeAddress(s, domain string, allowNull bool) (string, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("address contains a forbidden control character")
	}
	if s == "<>" && allowNull {
		return "", nil
	}
	if !strings.ContainsAny(s, "@<> ,:;\"") && s != "" {
		s += "@" + domain
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return "", fmt.Errorf("invalid address %q: %w", s, err)
	}
	// net/mail accepts some quoted local parts which net/smtp cannot safely put on the wire.
	if strings.ContainsAny(a.Address, "\r\n\x00<>") {
		return "", errors.New("unsupported envelope address")
	}
	return a.Address, nil
}

type headerField struct {
	name  string
	value string
}

func prepareMessage(in io.Reader, args []string, domain string, fromHeaders, ignoreDots bool) ([]byte, []string, error) {
	r := bufio.NewReader(in)
	var raw bytes.Buffer
	for {
		line, err := r.ReadBytes('\n')
		if !ignoreDots && bytes.Equal(bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r")), []byte(".")) {
			break
		}
		raw.Write(line)
		if err != nil {
			if err != io.EOF {
				return nil, nil, fmt.Errorf("read message: %w", err)
			}
			break
		}
	}
	data := raw.Bytes()
	if _, err := mail.ReadMessage(bytes.NewReader(data)); err != nil {
		return nil, nil, fmt.Errorf("invalid RFC 5322 message: %w", err)
	}
	// Preserve header bytes and MIME body exactly, removing blind-recipient fields and their folds.
	var clean bytes.Buffer
	var fields []headerField
	offset, skip, bodyFound := 0, false, false
	for offset < len(data) {
		end := bytes.IndexByte(data[offset:], '\n')
		if end < 0 {
			return nil, nil, errors.New("message has no header/body separator")
		}
		end += offset + 1
		line := data[offset:end]
		offset = end
		text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if text == "" {
			clean.Write(line)
			clean.Write(data[offset:])
			bodyFound = true
			break
		}
		if text[0] == ' ' || text[0] == '\t' {
			if len(fields) == 0 {
				return nil, nil, errors.New("header continuation has no preceding field")
			}
			fields[len(fields)-1].value += " " + strings.TrimSpace(text)
		} else {
			name, value, ok := strings.Cut(text, ":")
			if !ok {
				return nil, nil, errors.New("malformed message header")
			}
			name = strings.ToLower(name)
			fields = append(fields, headerField{name, strings.TrimSpace(value)})
			skip = name == "bcc" || name == "resent-bcc"
		}
		if !skip {
			clean.Write(line)
		}
	}
	if !bodyFound {
		return nil, nil, errors.New("message has no header/body separator")
	}
	recipients := append([]string(nil), args...)
	if fromHeaders {
		selected := fields
		resent := false
		for i, f := range fields {
			if strings.HasPrefix(f.name, "resent-") {
				selected = fields[i:]
				resent = true
				break
			}
		}
		seenResent := make(map[string]bool)
		for _, f := range selected {
			if resent {
				if !strings.HasPrefix(f.name, "resent-") {
					break
				}
				if seenResent[f.name] {
					break
				}
				seenResent[f.name] = true
			}
			prefix := ""
			if resent {
				prefix = "resent-"
			}
			if f.name != prefix+"to" && f.name != prefix+"cc" && f.name != prefix+"bcc" {
				continue
			}
			if strings.TrimSpace(f.value) == "" {
				continue
			}
			list, err := mail.ParseAddressList(f.value)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid %s header: %w", f.name, err)
			}
			for _, a := range list {
				recipients = append(recipients, a.Address)
			}
		}
	}
	seen := make(map[string]bool)
	var envelope []string
	for _, s := range recipients {
		a, err := envelopeAddress(s, domain, false)
		if err != nil {
			return nil, nil, fmt.Errorf("recipient: %w", err)
		}
		if !seen[a] {
			envelope = append(envelope, a)
			seen[a] = true
		}
	}
	if len(envelope) == 0 {
		return nil, nil, errors.New("no recipients; specify recipients or use -t")
	}
	return clean.Bytes(), envelope, nil
}
