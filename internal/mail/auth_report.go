package mail

import (
	"fmt"

	"github.com/jedib0t/go-pretty/v6/table"
)

func (r *TestReport) certificateAuthentication() bool {
	return r.authentication.Method == AuthMTLS || r.authentication.Method == AuthMTLSExternal
}

func (r *TestReport) authenticationTable() reportTable {
	auth := r.authentication
	policy := auth.ServerVerification
	trust := "Not established / policy not passed"
	if policy.PolicyPassed {
		trust = "Policy passed; trusted issuer"
		if policy.ExpiryExceptionUsed {
			trust += "; leaf expiry waived"
		}
		if policy.IssuerExceptionUsed {
			trust = "Policy passed under explicit issuer exception; untrusted anchor (not issuer-verified)"
			if policy.ExpiryExceptionUsed {
				trust += "; leaf expiry waived"
			}
		}
	}
	rows := []table.Row{
		{"Authentication method", string(auth.Method)},
		{"TLS established", fmt.Sprint(auth.TLSEstablished)},
		{"Client certificate requested", fmt.Sprint(auth.ClientCertificateRequested)},
		{"Client certificate presented", fmt.Sprint(auth.ClientCertificatePresented)},
		{"SMTP AUTH confirmed", fmt.Sprint(auth.SMTPAuthConfirmed)},
		{"Server root mode", string(policy.RootMode)},
		{"Server trust anchor SHA256", policy.AnchorSHA256},
		{"Server verification", trust},
		{"CA policy", fmt.Sprintf("allow configured=%t; deny configured=%t; policy passed=%t",
			policy.AllowConfigured, policy.DenyConfigured, policy.PolicyPassed)},
		{"Configured insecure options", fmt.Sprintf("expiry grace=%s; unverifiable issuer=%t", policy.ExpiryGrace, policy.IssuerExceptionConfigured)},
		{"Used verification exceptions", fmt.Sprintf("expired leaf=%t; untrusted issuer=%t", policy.ExpiryExceptionUsed, policy.IssuerExceptionUsed)},
	}
	if cert := auth.ClientCertificate; cert != nil {
		rows = append(rows,
			table.Row{"Client certificate subject", cert.Subject},
			table.Row{"Client certificate issuer", cert.Issuer},
			table.Row{"Client certificate SHA256", cert.SHA256},
			table.Row{"Client certificate key", cert.PublicKey},
			table.Row{"Client certificate signature", cert.SignatureAlgorithm},
			table.Row{"Client certificate provenance", "Local configured leaf metadata; not proof of relay-side certificate verification or identity mapping"})
	}
	return reportTable{header: table.Row{"Property", "Details"}, rows: rows,
		configs: []table.ColumnConfig{{Number: 2, WidthMax: 76}}}
}

func (r *TestReport) renderAuthentication(format reportFormat) string {
	t := r.authenticationTable()
	if format == reportPlain {
		t.header = nil
	}
	return reportNote(format, "Authentication evidence / local client certificate") + "\n" +
		t.render(format, r.color, r.values["AD domain"])
}

func (r *TestReport) cryptoNote() string {
	if !r.certificateAuthentication() {
		return cryptoReportNote
	}
	return "NIST SP 800-57 classical estimates, not certification or a post-quantum rating. " +
		"Client certificate key metadata is local, not a server-verified client path. " +
		"TLS handshake signature scheme and relay identity/authorization policy are not observable. " +
		"Key strength does not restore issuer trust or prove SMTP authentication or delivery."
}
