package mail

import (
	"fmt"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/otuschhoff/adbind/ad/kerberos"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
)

type certificateValidity struct {
	label      string
	start, end time.Time
}

const cryptoReportNote = "NIST SP 800-57 classical key-strength estimate, not certification, a post-quantum rating or a complete authentication-security assessment. " +
	"TLS handshake signature scheme is not exposed by Go. Kerberos ratings cover supported AES encryption keys, not ticket MACs or password entropy; legacy/unknown enctypes are not rated. " +
	"Ticket encryption, ticket session key and SSPI context protection are distinct; context attributes never substitute for ticket metadata."

const validityReportNote = "UTC start/end; age and remaining validity use the report snapshot time. " +
	"Kerberos start is effective ValidFrom: auth_time_fallback uses AuthTime; start_time_or_auth_time means the original optional StartTime was not retained. " +
	"SSPI context lifetime is separate from OS-managed/unavailable ticket validity."

func (r *TestReport) KerberosTicket(metadata kerberos.TicketMetadata) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ticketMetadata = metadata
}

func metadataValue[T any](field kerberos.MetadataField[T]) string {
	if field.Available {
		return fmt.Sprint(field.Value)
	}
	reason := field.Reason
	if reason == "" {
		reason = kerberos.MetadataNotProvided
	}
	return "Unavailable (" + string(reason) + ")"
}

func enctypeDetails(value kerberos.EnctypeMetadata) string {
	return fmt.Sprintf("%s; enctype=%s; encoded key=%s",
		metadataValue(value.Name), metadataValue(value.ID), metadataBits(value.NominalKeyBits))
}

func metadataBits(field kerberos.MetadataField[int]) string {
	value := metadataValue(field)
	if field.Available {
		value += " bit"
	}
	return value
}

func enctypeStrength(value kerberos.EnctypeMetadata) (int, string) {
	if !value.ID.Available {
		return 0, metadataValue(value.ID)
	}
	var bits int
	switch value.ID.Value {
	case etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA256_128:
		bits = 128
	case etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA384_192:
		bits = 256
	case etypeID.DES_CBC_CRC, etypeID.DES_CBC_MD4, etypeID.DES_CBC_MD5, etypeID.DES_CBC_RAW,
		etypeID.DES3_CBC_MD5, etypeID.DES3_CBC_RAW, etypeID.DES3_CBC_SHA1, etypeID.DES_HMAC_SHA1,
		etypeID.DES_EDE3_CBC_ENV_OID, etypeID.DES3_CBC_SHA1_KD, etypeID.RC4_HMAC, etypeID.RC4_HMAC_EXP:
		return 0, "Legacy / not rated"
	default:
		return 0, fmt.Sprintf("Unavailable (unsupported enctype %d)", value.ID.Value)
	}
	return bits, equivalentStrength(bits)
}

func hasSSPIContext(metadata kerberos.TicketMetadata) bool {
	return metadata.TicketEncryption.ID.Reason == kerberos.MetadataOSUnavailable ||
		metadata.Context.ValidFrom.Available || metadata.Context.Expires.Available ||
		metadata.Context.Name.Available || metadata.Context.AlgorithmID.Available
}

func (r *TestReport) cryptoTable() reportTable {
	rows := append([]table.Row(nil), r.tlsCrypto...)
	if len(rows) == 0 {
		rows = append(rows, table.Row{"TLS cryptography", "TLS not established / unavailable", "Unavailable"})
	}
	metadata := r.ticketMetadata
	ticketBits, ticketRating := enctypeStrength(metadata.TicketEncryption)
	sessionBits, sessionRating := enctypeStrength(metadata.SessionKey)
	rows = append(rows,
		table.Row{"Kerberos ticket encryption", enctypeDetails(metadata.TicketEncryption), ticketRating},
		table.Row{"Kerberos ticket session key", enctypeDetails(metadata.SessionKey), sessionRating},
	)
	ticketStrength := 0
	if ticketBits > 0 && sessionBits > 0 {
		ticketStrength = min(ticketBits, sessionBits)
	}
	rows = append(rows, table.Row{"Kerberos ticket strength",
		metadataValue(metadata.Service) + "@" + metadataValue(metadata.Realm) + "; weakest ticket/session-key encryption",
		equivalentStrength(ticketStrength)})
	if hasSSPIContext(metadata) {
		rows = append(rows, table.Row{"SSPI context protection",
			fmt.Sprintf("%s; Windows ALG_ID=%s; encoded key=%s",
				metadataValue(metadata.Context.Name), metadataValue(metadata.Context.AlgorithmID), metadataBits(metadata.Context.KeyBits)),
			"Unavailable (context algorithm not assessed)"})
	}
	overall := 0
	if r.tlsStrength > 0 && ticketStrength > 0 {
		overall = min(r.tlsStrength, ticketStrength)
	}
	rows = append(rows, table.Row{"Overall strength", "Weakest supported TLS and Kerberos encryption-key component", equivalentStrength(overall)})
	if overall == 0 {
		reason := "Kerberos ticket encryption or session-key strength unavailable / not rated"
		if r.tlsStrength == 0 {
			reason = r.tlsStrengthReason
			if reason == "" {
				reason = "TLS strength unavailable"
			}
		}
		rows = append(rows, table.Row{"Overall estimate limitation", reason, "-"})
	}
	return reportTable{header: table.Row{"Property", "Cryptography", "NIST strength"}, rows: rows,
		configs: []table.ColumnConfig{{Number: 2, WidthMax: 76},
			{Number: 3, Align: text.AlignRight, AlignHeader: text.AlignRight}}}
}

func (r *TestReport) renderCrypto(format reportFormat) string {
	t := r.cryptoTable()
	if format == reportPlain {
		t.header = nil
		rows := t.rows
		t.rows = make([]table.Row, len(rows))
		for i, row := range rows {
			detail := fmt.Sprint(row[1])
			if row[2] != "-" {
				detail += " (" + fmt.Sprint(row[2]) + ")"
			}
			t.rows[i] = table.Row{row[0], detail}
		}
	}
	return reportNote(format, "Cryptography (TLS / Kerberos)") + "\n" +
		t.render(format, r.color, r.values["AD domain"]) + "\n" +
		reportNote(format, cryptoReportNote)
}

func relativeValidityDuration(duration time.Duration) string {
	var count time.Duration
	var unit string
	switch {
	case duration >= 24*time.Hour:
		count, unit = duration/(24*time.Hour), "day"
	case duration >= time.Hour:
		count, unit = duration/time.Hour, "hour"
	case duration >= time.Minute:
		count, unit = duration/time.Minute, "minute"
	default:
		return formatDuration(duration)
	}
	if count != 1 {
		unit += "s"
	}
	return fmt.Sprintf("%d %s", count, unit)
}

func validityTime(field kerberos.MetadataField[time.Time]) string {
	if !field.Available {
		return metadataValue(field)
	}
	if field.Value.IsZero() {
		return "Unavailable (invalid timestamp)"
	}
	return field.Value.UTC().Format(time.RFC3339)
}

func (r *TestReport) validityTable() reportTable {
	t := reportTable{header: table.Row{"Object", "Start (UTC)", "End (UTC)", "Age", "Remaining", "Start source"},
		configs: []table.ColumnConfig{
			{Number: 4, Align: text.AlignRight, AlignHeader: text.AlignRight},
			{Number: 5, Align: text.AlignRight, AlignHeader: text.AlignRight},
		}}
	now := r.snapshotTime()
	appendValidity := func(label string, start, end kerberos.MetadataField[time.Time]) {
		age, remaining, source := validityTime(start), validityTime(end), "-"
		if start.Available && !start.Value.IsZero() {
			source = string(start.Provenance)
			age = relativeValidityDuration(now.Sub(start.Value))
			if start.Value.After(now) {
				age = "Starts in " + relativeValidityDuration(start.Value.Sub(now))
			}
		}
		if end.Available && !end.Value.IsZero() {
			remaining = "+" + relativeValidityDuration(end.Value.Sub(now))
			if !end.Value.After(now) {
				remaining = "Expired " + relativeValidityDuration(now.Sub(end.Value)) + " ago"
			}
		}
		t.rows = append(t.rows, table.Row{label, validityTime(start), validityTime(end), age, remaining, source})
	}
	for _, cert := range r.tlsValidity {
		start := kerberos.MetadataField[time.Time]{Value: cert.start, Available: !cert.start.IsZero(), Provenance: "tls_certificate", Reason: kerberos.MetadataNotPresent}
		end := kerberos.MetadataField[time.Time]{Value: cert.end, Available: !cert.end.IsZero(), Provenance: "tls_certificate", Reason: kerberos.MetadataNotPresent}
		appendValidity(cert.label, start, end)
	}
	if len(r.tlsValidity) == 0 {
		appendValidity("TLS certificate", kerberos.MetadataField[time.Time]{Reason: kerberos.MetadataNotEstablished},
			kerberos.MetadataField[time.Time]{Reason: kerberos.MetadataNotEstablished})
	}
	metadata := r.ticketMetadata
	label := "Kerberos SMTP service ticket"
	if metadata.Service.Available {
		label += " (" + metadata.Service.Value + ")"
	}
	appendValidity(label, metadata.ValidFrom, metadata.EndTime)
	if hasSSPIContext(metadata) {
		appendValidity("SSPI security context (not ticket validity)", metadata.Context.ValidFrom, metadata.Context.Expires)
	}
	return t
}

func (r *TestReport) renderValidity(format reportFormat) string {
	return reportNote(format, "Validity (TLS certificates / Kerberos)") + "\n" +
		r.validityTable().render(format, r.color, r.values["AD domain"]) + "\n" +
		reportNote(format, validityReportNote)
}
