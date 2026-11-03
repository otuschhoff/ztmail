package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otuschhoff/adbind/ad/kerberos"
)

func TestCredentialSourceReportPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KRB5CCNAME", "FILE:"+filepath.Join(dir, "default.cache"))
	for _, tc := range []struct {
		name string
		o    options
		path string
	}{
		{"keytab", options{auth: "auto", keytab: filepath.Join(dir, "mail.keytab")}, filepath.Join(dir, "mail.keytab")},
		{"cache", options{auth: "auto", ccache: filepath.Join(dir, "mail.cache")}, filepath.Join(dir, "mail.cache")},
		{"environment", options{auth: "ccache"}, filepath.Join(dir, "default.cache")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			credentials, err := credentialOptions(tc.o)
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			report := newTestReport(&output, false)
			reportCredentialSource(report, credentials.Source, credentials)
			var result error
			report.Finish(&result)
			if result != nil || !strings.Contains(output.String(), string(credentials.Source)+" ("+tc.path+")") {
				t.Fatalf("missing resolved credential path: err=%v\n%s", result, &output)
			}
		})
	}
}

func TestCredentialSourcePathClearedOnFallback(t *testing.T) {
	var output bytes.Buffer
	report := newTestReport(&output, false)
	reportCredentialSource(report, kerberos.SourceKeytab, kerberos.Options{Keytab: "/old.keytab"})
	reportCredentialSource(report, kerberos.SourcePassword, kerberos.Options{})
	var err error
	report.Finish(&err)
	if err != nil || strings.Contains(output.String(), "/old.keytab") || !strings.Contains(output.String(), "password") {
		t.Fatalf("stale credential path after password fallback: %v\n%s", err, &output)
	}
}

func TestCredentialSourceUnknownPathDoesNotGuess(t *testing.T) {
	var output bytes.Buffer
	report := newTestReport(&output, false)
	reportCredentialSource(report, kerberos.SourceCCache, kerberos.Options{})
	var err error
	report.Finish(&err)
	if err != nil || strings.Contains(output.String(), "ccache (") || !strings.Contains(output.String(), "ccache") {
		t.Fatalf("invented cache path: %v\n%s", err, &output)
	}
}
