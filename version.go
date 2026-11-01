package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const semver = "0.1.1"
const buildTimeLayout = "20060102-150405"

// These are injected by the Makefile and GitHub Actions build.
var buildTime, commitSHA string

func fullVersion() (string, error) {
	if _, err := time.Parse(buildTimeLayout, buildTime); err != nil {
		return "", fmt.Errorf("missing or invalid UTC build time; build with make build: %w", err)
	}
	if len(commitSHA) != 7 || strings.Trim(commitSHA, "0123456789abcdef") != "" {
		return "", errors.New("missing or invalid seven-character commit SHA; build with make build")
	}
	return semver + "+" + buildTime + "." + commitSHA, nil
}
