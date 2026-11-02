package mail

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"strings"
)

func EnvelopeAddress(s, domain string, allowNull bool) (string, error) {
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

func invalidMessage(err error) error {
	return fmt.Errorf("invalid RFC 5322 message: %w\n"+
		"Each header must use \"Name: value\". Insert a blank line between the last header and the body "+
		"(press Enter twice after the last header).\n"+
		"The message was rejected locally; nothing was sent to the mail gateway.", err)
}

func PrepareMessage(in io.Reader, args []string, domain string, fromHeaders, ignoreDots bool) ([]byte, []string, error) {
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
	if len(data) == 0 {
		return nil, nil, invalidMessage(errors.New("message input is empty"))
	}
	// Preserve header bytes and MIME body exactly, removing blind-recipient fields and their folds.
	var clean bytes.Buffer
	var fields []headerField
	offset, skip, bodyFound := 0, false, false
	lineNumber := 0
	for offset < len(data) {
		end := bytes.IndexByte(data[offset:], '\n')
		if end < 0 {
			return nil, nil, invalidMessage(errors.New("missing blank line separating headers from the body"))
		}
		end += offset + 1
		line := data[offset:end]
		offset = end
		lineNumber++
		text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if text == "" {
			clean.Write(line)
			clean.Write(data[offset:])
			bodyFound = true
			break
		}
		if text[0] == ' ' || text[0] == '\t' {
			if len(fields) == 0 {
				return nil, nil, invalidMessage(fmt.Errorf("line %d: header continuation has no preceding field", lineNumber))
			}
			fields[len(fields)-1].value += " " + strings.TrimSpace(text)
		} else {
			name, value, ok := strings.Cut(text, ":")
			if !ok || name == "" {
				return nil, nil, invalidMessage(fmt.Errorf("line %d: expected a header before the blank line, but this line is not \"Name: value\"", lineNumber))
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
		return nil, nil, invalidMessage(errors.New("missing blank line separating headers from the body"))
	}
	if _, err := mail.ReadMessage(bytes.NewReader(data)); err != nil {
		return nil, nil, invalidMessage(err)
	}
	recipients := append([]string(nil), args...)
	if fromHeaders || len(args) == 0 {
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
		a, err := EnvelopeAddress(s, domain, false)
		if err != nil {
			return nil, nil, fmt.Errorf("recipient: %w", err)
		}
		if !seen[a] {
			envelope = append(envelope, a)
			seen[a] = true
		}
	}
	return clean.Bytes(), envelope, nil
}

func RecipientFallback(recipients []string, canonical, domain string) ([]string, error) {
	if len(recipients) > 0 {
		return recipients, nil
	}
	if canonical == "" {
		return nil, errors.New("no recipients in arguments or headers and authenticated user's canonical mail is unavailable")
	}
	address, err := EnvelopeAddress(canonical, domain, false)
	if err != nil {
		return nil, fmt.Errorf("self-recipient fallback: %w", err)
	}
	return []string{address}, nil
}

func ApplySender(message []byte, explicit, canonical, domain string) ([]byte, string, error) {
	if explicit == "<>" {
		return message, "", nil
	}
	sender := explicit
	if sender == "" {
		sender = canonical
	}
	if sender == "" {
		return nil, "", errors.New("authenticated AD identity has no canonical sender; specify -f")
	}
	envelope, err := EnvelopeAddress(sender, domain, false)
	if err != nil {
		return nil, "", fmt.Errorf("selected sender: %w", err)
	}
	rewritten, err := RewriteSender(message, envelope)
	return rewritten, envelope, err
}

func RewriteSender(message []byte, sender string) ([]byte, error) {
	address, err := mail.ParseAddress(sender)
	if err != nil || address.Name != "" || address.Address != sender || strings.ContainsAny(sender, "\r\n\x00") {
		return nil, errors.New("sender rewrite requires a single bare mailbox")
	}
	newline := "\n"
	if first := bytes.IndexByte(message, '\n'); first > 0 && message[first-1] == '\r' {
		newline = "\r\n"
	}
	var out bytes.Buffer
	out.WriteString("From: " + address.String() + newline)
	skip, senderWritten := false, false
	for offset := 0; offset < len(message); {
		end := bytes.IndexByte(message[offset:], '\n')
		if end < 0 {
			break
		}
		end += offset + 1
		line := message[offset:end]
		offset = end
		text := strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r")
		if text == "" {
			out.Write(line)
			out.Write(message[offset:])
			return out.Bytes(), nil
		}
		if text[0] != ' ' && text[0] != '\t' {
			name, _, found := strings.Cut(text, ":")
			if !found {
				return nil, errors.New("malformed header during sender rewrite")
			}
			skip = strings.EqualFold(name, "from") || strings.EqualFold(name, "sender")
			if strings.EqualFold(name, "sender") && !senderWritten {
				out.WriteString("Sender: " + address.String() + newline)
				senderWritten = true
			}
		}
		if !skip {
			out.Write(line)
		}
	}
	return nil, errors.New("message has no header/body separator for sender rewrite")
}
