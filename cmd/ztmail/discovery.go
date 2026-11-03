package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var errHostDomainUnavailable = errors.New("host AD domain unavailable")

func hostDomain(host string) string {
	_, domain, found := strings.Cut(host, ".")
	if !found || domain == "localdomain" || domain == "localhost" {
		return ""
	}
	return domain
}

func discoverHost(ctx context.Context, override string) (string, string, error) {
	host, err := platformHostname()
	if err != nil {
		return "", "", fmt.Errorf("read host DNS name: %w", err)
	}
	host, err = dnsName(host)
	if err != nil {
		return "", "", fmt.Errorf("host name: %w", err)
	}
	if override != "" {
		domain, err := dnsName(override)
		if err != nil {
			return "", "", fmt.Errorf("--domain: %w", err)
		}
		if hostDomain(host) == "" {
			host = strings.Split(host, ".")[0] + "." + domain
		}
		return host, domain, nil
	}
	if domain := hostDomain(host); domain != "" {
		return host, domain, nil
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	domain, suffixErr := platformDomain()
	if suffixErr == nil && domain != "" {
		domain, err = dnsName(domain)
		if err == nil {
			return strings.Split(host, ".")[0] + "." + domain, domain, nil
		}
		suffixErr = err
	}
	return "", "", fmt.Errorf("cannot discover host DNS domain; specify --domain: %w",
		errors.Join(errHostDomainUnavailable, errors.New("no fully qualified host name or usable DNS suffix"), suffixErr))
}
