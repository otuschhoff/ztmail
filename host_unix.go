//go:build linux || darwin

package main

import (
	"bufio"
	"errors"
	"os"
	"strings"
)

func platformHostname() (string, error) { return os.Hostname() }

func platformDomain() (string, error) {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var domain string
	for scanner.Scan() {
		line := strings.SplitN(strings.SplitN(scanner.Text(), "#", 2)[0], ";", 2)[0]
		fields := strings.Fields(line)
		if len(fields) >= 2 && (fields[0] == "search" || fields[0] == "domain") {
			domain = fields[1]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	if domain == "" {
		return "", errors.New("no DNS search/domain suffix in /etc/resolv.conf")
	}
	return domain, nil
}
