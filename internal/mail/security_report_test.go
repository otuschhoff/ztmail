package mail

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
)

func testMetadataField[T any](value T, source kerberos.MetadataProvenance) kerberos.MetadataField[T] {
	return kerberos.MetadataField[T]{Value: value, Available: true, Provenance: source}
}

func testEnctype(id int32, bits int) kerberos.EnctypeMetadata {
	return kerberos.EnctypeMetadata{
		ID:             testMetadataField(id, kerberos.MetadataTicket),
		Name:           testMetadataField(etypeID.ETypesByID[id], kerberos.MetadataEnctypeRegistry),
		NominalKeyBits: testMetadataField(bits, kerberos.MetadataEnctypeRegistry),
	}
}

func testTicketMetadata(now time.Time) kerberos.TicketMetadata {
	return kerberos.TicketMetadata{
		Service:          testMetadataField("smtp/mailgw.corp.example", kerberos.MetadataTicket),
		Realm:            testMetadataField("CORP.EXAMPLE", kerberos.MetadataTicket),
		TicketEncryption: testEnctype(etypeID.AES128_CTS_HMAC_SHA1_96, 128),
		SessionKey:       testEnctype(etypeID.AES256_CTS_HMAC_SHA1_96, 256),
		AuthTime:         testMetadataField(now.Add(-2*time.Hour), kerberos.MetadataCredential),
		StartTime:        kerberos.MetadataField[time.Time]{Reason: kerberos.MetadataNotRetained},
		ValidFrom:        testMetadataField(now.Add(-2*time.Hour), kerberos.MetadataNormalizedStart),
		EndTime:          testMetadataField(now.Add(8*time.Hour), kerberos.MetadataCredential),
	}
}

func securityTableRow(t *testing.T, source reportTable, label string) table.Row {
	t.Helper()
	for _, row := range source.rows {
		if row[0] == label {
			return row
		}
	}
	t.Fatalf("missing row %q in %v", label, source.rows)
	return nil
}

func TestSecurityTablesSplitAndWeakestComponent(t *testing.T) {
	now := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	report := NewTestReport(io.Discard, false)
	report.snapshotAt = now
	state := strongTLSState()
	state.PeerCertificates[0].NotBefore = now.Add(-24 * 24 * time.Hour)
	state.PeerCertificates[0].NotAfter = now.Add(69 * 24 * time.Hour)
	report.TLS(state)
	report.KerberosTicket(testTicketMetadata(now))
	for _, row := range report.tlsDetailsTable().rows {
		if len(row) != 2 {
			t.Fatalf("certificate details have unexpected columns: %v", row)
		}
		for _, forbidden := range []string{"Cipher suite", "Key exchange", "Certificate key", "Valid from", "Valid until"} {
			if row[0] == forbidden {
				t.Fatalf("%s was not split out of certificate details", forbidden)
			}
		}
	}
	crypto := report.cryptoTable()
	for _, source := range []reportTable{crypto, report.validityTable()} {
		html := source.render(reportHTML, false, "")
		for _, config := range source.configs {
			if config.Align == 0 || config.Number == 0 {
				continue
			}
			label := source.header[config.Number-1].(string)
			want := `text-align:right;padding:8px;border:1px solid #d1d5db;background:#f3f4f6">` + label
			if !strings.Contains(html, want) {
				t.Errorf("security column %q is not right-aligned:\n%s", label, html)
			}
		}
	}
	for label, want := range map[string]string{
		"TLS overall strength":        "~192bit",
		"Kerberos ticket encryption":  "~128bit",
		"Kerberos ticket session key": "~256bit",
		"Kerberos ticket strength":    "~128bit",
		"Overall strength":            "~128bit",
	} {
		if got := securityTableRow(t, crypto, label)[2]; got != want {
			t.Errorf("%s = %v, want %s", label, got, want)
		}
	}
	validity := report.validityTable()
	cert := securityTableRow(t, validity, "TLS certificate 1 (CN=smtp.corp.example)")
	if cert[3] != "24 days" || cert[4] != "+69 days" || cert[5] != "tls_certificate" {
		t.Errorf("certificate relative validity is incorrect: %v", cert)
	}
	ticket := securityTableRow(t, validity, "Kerberos SMTP service ticket (smtp/mailgw.corp.example)")
	if ticket[1] != now.Add(-2*time.Hour).Format("2006-01-02 15:04") ||
		ticket[2] != now.Add(8*time.Hour).Format("2006-01-02 15:04") ||
		ticket[3] != "2 hours" || ticket[4] != "+8 hours" || ticket[5] != string(kerberos.MetadataNormalizedStart) {
		t.Errorf("ticket effective validity/provenance is incorrect: %v", ticket)
	}
	for _, format := range []reportFormat{reportTerminal, reportHTML, reportPlain} {
		result := report.renderTLSDetails(format)
		for _, want := range []string{"Cryptography (TLS / Kerberos)", "Validity (TLS certificates / Kerberos)",
			"Kerberos ticket encryption", "Kerberos ticket session key", "+69 days", "+8 hours"} {
			if !strings.Contains(result, want) {
				t.Errorf("format=%v: missing %q:\n%s", format, want, result)
			}
		}
	}
}

func TestCertificateChainValidityDeduplicatesAndLimitsStrength(t *testing.T) {
	now := time.Now()
	state := strongTLSState()
	root := &x509.Certificate{Subject: pkix.Name{CommonName: "root.corp.example"}, PublicKey: testRSAKey(2048),
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)}
	state.PeerCertificates = append(state.PeerCertificates, root)
	state.VerifiedChains = [][]*x509.Certificate{{state.PeerCertificates[0], root}}
	report := NewTestReport(io.Discard, false)
	report.TLS(state)
	report.KerberosTicket(testTicketMetadata(now))
	if len(report.tlsValidity) != 2 {
		t.Fatalf("certificate validity duplicated: %v", report.tlsValidity)
	}
	if got := securityTableRow(t, report.cryptoTable(), "Overall strength")[2]; got != "~112bit" {
		t.Errorf("weak chain key not reflected in combined estimate: %v", got)
	}
}

func TestKerberosEnctypeStrengthDoesNotGuess(t *testing.T) {
	for _, test := range []struct {
		id         int32
		bits, want int
		rating     string
	}{
		{17, 128, 128, "~128bit"}, {18, 256, 256, "~256bit"},
		{19, 128, 128, "~128bit"}, {20, 256, 256, "~256bit"},
		{23, 128, 0, "Legacy / not rated"}, {24, 128, 0, "Legacy / not rated"},
		{3, 64, 0, "Legacy / not rated"}, {16, 192, 0, "Legacy / not rated"},
		{0xffff, 4096, 0, "Unavailable (unsupported enctype 65535)"},
	} {
		bits, rating := enctypeStrength(testEnctype(test.id, test.bits))
		if bits != test.want || rating != test.rating {
			t.Errorf("enctype=%d: got %d %q, want %d %q", test.id, bits, rating, test.want, test.rating)
		}
	}
	unknown := kerberos.EnctypeMetadata{NominalKeyBits: testMetadataField(256, kerberos.MetadataEnctypeRegistry)}
	if bits, _ := enctypeStrength(unknown); bits != 0 {
		t.Fatal("guessed encryption strength from nominal key size without an enctype")
	}
	report := NewTestReport(io.Discard, false)
	report.TLS(strongTLSState())
	metadata := testTicketMetadata(time.Now())
	metadata.SessionKey = testEnctype(etypeID.RC4_HMAC, 128)
	report.KerberosTicket(metadata)
	if got := securityTableRow(t, report.cryptoTable(), "Overall strength")[2]; got != "Unavailable" {
		t.Fatalf("legacy component received an overall rating: %v", got)
	}
}

func TestSSPIContextIsNotTicketMetadata(t *testing.T) {
	now := time.Now().UTC()
	metadata := kerberos.TicketMetadata{
		TicketEncryption: kerberos.EnctypeMetadata{ID: kerberos.MetadataField[int32]{Reason: kerberos.MetadataOSUnavailable}},
		ValidFrom:        kerberos.MetadataField[time.Time]{Reason: kerberos.MetadataOSUnavailable},
		EndTime:          kerberos.MetadataField[time.Time]{Reason: kerberos.MetadataOSUnavailable},
		Context: kerberos.ContextMetadata{
			ValidFrom:   testMetadataField(now.Add(-time.Hour), kerberos.MetadataSSPIContext),
			Expires:     testMetadataField(now.Add(10*time.Hour), kerberos.MetadataSSPIContext),
			AlgorithmID: testMetadataField(uint32(0x6610), kerberos.MetadataSSPIContext),
			Name:        testMetadataField("AES256", kerberos.MetadataSSPIContext),
			KeyBits:     testMetadataField(256, kerberos.MetadataSSPIContext),
		},
	}
	report := NewTestReport(io.Discard, false)
	report.snapshotAt = now
	report.TLS(strongTLSState())
	report.KerberosTicket(metadata)
	crypto := report.cryptoTable()
	context := securityTableRow(t, crypto, "SSPI context protection")
	if !strings.Contains(context[1].(string), "AES256") || !strings.Contains(context[2].(string), "not assessed") {
		t.Errorf("SSPI crypto attributes not kept separate: %v", context)
	}
	if securityTableRow(t, crypto, "Overall strength")[2] != "Unavailable" {
		t.Fatal("SSPI context attributes substituted for ticket strength")
	}
	ticket := securityTableRow(t, report.validityTable(), "Kerberos SMTP service ticket")
	if ticket[1] != "Unavailable (os_managed_ticket_unavailable)" || ticket[2] != ticket[1] {
		t.Errorf("SSPI context expiry substituted for ticket expiry: %v", ticket)
	}
	contextValidity := securityTableRow(t, report.validityTable(), "SSPI security context (not ticket validity)")
	if contextValidity[3] != "1 hour" || contextValidity[4] != "+10 hours" {
		t.Errorf("SSPI context lifetime unavailable: %v", contextValidity)
	}
}

func TestValidityFutureExpiredAndUnavailable(t *testing.T) {
	now := time.Now().UTC()
	report := NewTestReport(io.Discard, false)
	report.snapshotAt = now
	report.tlsValidity = []certificateValidity{
		{"Future cert", now.Add(time.Hour), now.Add(2 * time.Hour)},
		{"Expired cert", now.Add(-2 * time.Hour), now.Add(-time.Hour)},
	}
	report.KerberosTicket(kerberos.Ticket{}.Metadata())
	if age := securityTableRow(t, report.validityTable(), "Future cert")[3]; age != "Starts in 1 hour" {
		t.Errorf("future start incorrectly reported: %v", age)
	}
	if remaining := securityTableRow(t, report.validityTable(), "Expired cert")[4]; remaining != "Expired 1 hour ago" {
		t.Errorf("expired end incorrectly reported: %v", remaining)
	}
	ticket := securityTableRow(t, report.validityTable(), "Kerberos SMTP service ticket")
	if ticket[1] != "Unavailable (not_provided)" || ticket[4] != "Unavailable (not_provided)" {
		t.Errorf("missing ticket validity invented: %v", ticket)
	}
	metadata := testTicketMetadata(now)
	metadata.ValidFrom = testMetadataField(now.Add(-2*time.Hour), kerberos.MetadataAuthTime)
	report.KerberosTicket(metadata)
	if source := securityTableRow(t, report.validityTable(), "Kerberos SMTP service ticket (smtp/mailgw.corp.example)")[5]; source != string(kerberos.MetadataAuthTime) {
		t.Errorf("AuthTime fallback provenance not retained: %v", source)
	}
}

var _ kerberos.TicketMetadataProvider = (*adSecurityContext)(nil)
var _ SecurityContext = (*adSecurityContext)(nil)
