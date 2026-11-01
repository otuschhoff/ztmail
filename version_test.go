package main

import (
	"bytes"
	"strings"
	"testing"
)

func setBuildMetadata(t *testing.T, stamp, sha string) {
	t.Helper()
	originalTime, originalSHA := buildTime, commitSHA
	buildTime, commitSHA = stamp, sha
	t.Cleanup(func() { buildTime, commitSHA = originalTime, originalSHA })
}

func TestFullVersion(t *testing.T) {
	setBuildMetadata(t, "20261101-110716", "abcdef0")
	got, err := fullVersion()
	if err != nil || got != "0.1.0+20261101-110716.abcdef0" {
		t.Fatalf("version=%q err=%v", got, err)
	}
}

func TestFullVersionRejectsMissingOrInvalidMetadata(t *testing.T) {
	for _, tt := range []struct{ stamp, sha string }{
		{"", "abcdef0"},
		{"20260230-120000", "abcdef0"},
		{"20261101-250000", "abcdef0"},
		{"2026-11-01", "abcdef0"},
		{"20261101-110716", ""},
		{"20261101-110716", "abcdef01"},
		{"20261101-110716", "abcxyz0"},
	} {
		t.Run(tt.stamp+"."+tt.sha, func(t *testing.T) {
			setBuildMetadata(t, tt.stamp, tt.sha)
			if _, err := fullVersion(); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}

func TestVersionFlagDoesNotReadMessageOrAcquireCredentials(t *testing.T) {
	setBuildMetadata(t, "20261101-110716", "123abcd")
	cmd := newCommand()
	cmd.SetArgs([]string{"--version"})
	cmd.SetIn(failingReader{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "0.1.0+20261101-110716.123abcd\n" {
		t.Fatalf("output=%q", out.String())
	}
}

func TestVersionFlagReportsUnversionedBuild(t *testing.T) {
	setBuildMetadata(t, "", "")
	cmd := newCommand()
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "make build") {
		t.Fatalf("expected explicit metadata error, got %v", err)
	}
}
