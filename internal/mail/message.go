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
	return mailboxSpec(a.Address)
}

func mailboxSpec(address string) (string, error) {
	if strings.ContainsAny(address, "\r\n\x00<>") {
		return "", errors.New("unsupported envelope address")
	}
	// ParseAddress decodes local-part quotes; String restores required quoting and escaping.
	formatted := (&mail.Address{Address: address}).String()
	return formatted[1 : len(formatted)-1], nil
}

func bareMailboxSpec(s string) (string, error) {
	address, err := mail.ParseAddress(s)
	if err != nil || address.Name != "" || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("requires a single bare mailbox")
	}
	at := strings.LastIndexByte(s, '@')
	if at < 1 {
		return "", errors.New("requires a single bare mailbox")
	}
	local := s[:at]
	if strings.HasPrefix(local, "\"") {
		if len(local) < 2 || local[len(local)-1] != '"' {
			return "", errors.New("requires a single bare mailbox")
		}
		for i := 1; i < len(local)-1; i++ {
			if local[i] == '\\' {
				i++
			} else if local[i] == '"' {
				return "", errors.New("requires a single bare mailbox")
			}
		}
		domainAt := strings.LastIndexByte(address.Address, '@')
		if s[at+1:] != address.Address[domainAt+1:] {
			return "", errors.New("requires a single bare mailbox")
		}
	} else if s != address.Address {
		return "", errors.New("requires a single bare mailbox")
	}
	return mailboxSpec(address.Address)
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 33 || name[i] > 126 || name[i] == ':' {
			return false
		}
	}
	return true
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
	return prepareMessage(in, args, domain, fromHeaders, ignoreDots, false)
}

// PrepareMessageBytes preserves dot lines and returns independently owned message bytes and recipients.
func PrepareMessageBytes(data []byte, args []string, domain string, fromHeaders bool) ([]byte, []string, error) {
	return prepareMessageBytes(data, args, domain, fromHeaders, false)
}

func PrepareLocalMessage(in io.Reader, args []string, fromHeaders, ignoreDots bool) ([]byte, []string, error) {
	return prepareMessage(in, args, "", fromHeaders, ignoreDots, true)
}

func LocalEnvelopeAddress(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n\x00/|:") {
		return "", errors.New("native recipients must be mailboxes or simple local aliases, not file, pipe or include targets")
	}
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.+-") == "" {
		return s, nil
	}
	return EnvelopeAddress(s, "", false)
}

func prepareMessage(in io.Reader, args []string, domain string, fromHeaders, ignoreDots, local bool) ([]byte, []string, error) {
	r := bufio.NewReader(in)
	var raw bytes.Buffer
	partial := false
	for {
		line, err := r.ReadSlice('\n')
		if !ignoreDots && !partial && bytes.Equal(bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r")), []byte(".")) {
			break
		}
		raw.Write(line)
		if err == bufio.ErrBufferFull {
			partial = true
			continue
		}
		if err != nil {
			if err != io.EOF {
				return nil, nil, fmt.Errorf("read message: %w", err)
			}
			break
		}
		partial = false
	}
	return prepareMessageBytes(raw.Bytes(), args, domain, fromHeaders, local)
}

func prepareMessageBytes(data []byte, args []string, domain string, fromHeaders, local bool) ([]byte, []string, error) {
	if len(data) == 0 {
		return nil, nil, invalidMessage(errors.New("message input is empty"))
	}
	// Preserve header bytes and MIME body exactly, removing blind-recipient fields and their folds.
	var clean bytes.Buffer
	var fields []headerField
	var foldedValue strings.Builder
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
			field := &fields[len(fields)-1]
			if foldedValue.Len() == 0 {
				foldedValue.WriteString(field.value)
			}
			foldedValue.WriteByte(' ')
			foldedValue.WriteString(strings.TrimSpace(text))
			field.value = foldedValue.String()
		} else {
			foldedValue.Reset()
			name, value, ok := strings.Cut(text, ":")
			if !ok || name == "" {
				return nil, nil, invalidMessage(fmt.Errorf("line %d: expected a header before the blank line, but this line is not \"Name: value\"", lineNumber))
			}
			if !validHeaderName(name) {
				return nil, nil, invalidMessage(fmt.Errorf("line %d: invalid header field name %q", lineNumber, name))
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
				spec, err := mailboxSpec(a.Address)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid %s header: %w", f.name, err)
				}
				recipients = append(recipients, spec)
			}
		}
	}
	seen := make(map[string]bool)
	var envelope []string
	for _, s := range recipients {
		var a string
		var err error
		if local {
			a, err = LocalEnvelopeAddress(s)
		} else {
			a, err = EnvelopeAddress(s, domain, false)
		}
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
	spec, err := bareMailboxSpec(sender)
	if err != nil {
		return nil, errors.New("sender rewrite requires a single bare mailbox")
	}
	newline := "\n"
	if first := bytes.IndexByte(message, '\n'); first > 0 && message[first-1] == '\r' {
		newline = "\r\n"
	}
	var out bytes.Buffer
	out.WriteString("From: <" + spec + ">" + newline)
	skip, senderWritten, fieldSeen := false, false, false
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
		if text[0] == ' ' || text[0] == '\t' {
			if !fieldSeen {
				return nil, errors.New("malformed header during sender rewrite")
			}
		} else {
			name, _, found := strings.Cut(text, ":")
			if !found || !validHeaderName(name) {
				return nil, errors.New("malformed header during sender rewrite")
			}
			fieldSeen = true
			skip = strings.EqualFold(name, "from") || strings.EqualFold(name, "sender")
			if strings.EqualFold(name, "sender") && !senderWritten {
				out.WriteString("Sender: <" + spec + ">" + newline)
				senderWritten = true
			}
		}
		if !skip {
			out.Write(line)
		}
	}
	return nil, errors.New("message has no header/body separator for sender rewrite")
}
