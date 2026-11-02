package mail

import (
	"errors"
	"net"
	"strings"
)

func DNSName(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) == 0 || len(s) > 253 || net.ParseIP(s) != nil {
		return "", errors.New("expected a DNS hostname, not an IP address or empty name")
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid DNS label")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("DNS names must contain ASCII letters, digits, dots, or hyphens")
			}
		}
	}
	return s, nil
}
