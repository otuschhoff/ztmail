package mail

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
)

func publicKeyStrength(key any) (string, int) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil {
			return "RSA key unavailable", 0
		}
		bits := key.N.BitLen()
		// NIST SP 800-57 Part 1 Rev. 5, Table 2; round down between tiers.
		for _, tier := range []struct{ size, strength int }{
			{15360, 256}, {7680, 192}, {3072, 128}, {2048, 112}, {1024, 80},
		} {
			if bits >= tier.size {
				return fmt.Sprintf("RSA %d-bit", bits), tier.strength
			}
		}
		return fmt.Sprintf("RSA %d-bit", bits), 0
	case *ecdsa.PublicKey:
		if key == nil || key.Curve == nil {
			return "ECDSA key unavailable", 0
		}
		params := key.Curve.Params()
		strength := map[int]int{224: 112, 256: 128, 384: 192, 521: 256}[params.BitSize]
		return fmt.Sprintf("ECDSA %s (%d-bit)", params.Name, params.BitSize), strength
	case ed25519.PublicKey:
		if len(key) == ed25519.PublicKeySize {
			return "Ed25519 (256-bit)", 128
		}
		return "Ed25519 key unavailable", 0
	default:
		return fmt.Sprintf("Unsupported public key (%T)", key), 0
	}
}

func signatureStrength(algorithm x509.SignatureAlgorithm) int {
	switch algorithm {
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256:
		return 128
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		return 192
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		return 256
	case x509.PureEd25519:
		return 128
	default:
		return 0
	}
}

func keyExchangeStrength(state tls.ConnectionState) (string, int) {
	switch state.CurveID {
	case tls.CurveP256, tls.X25519:
		return state.CurveID.String(), 128
	case tls.CurveP384:
		return state.CurveID.String(), 192
	case tls.CurveP521:
		return state.CurveID.String(), 256
	case tls.X25519MLKEM768:
		return state.CurveID.String() + " (classical X25519 component only)", 128
	case tls.SecP256r1MLKEM768:
		return state.CurveID.String() + " (classical P-256 component only)", 128
	case tls.SecP384r1MLKEM1024:
		return state.CurveID.String() + " (classical P-384 component only)", 192
	case 0:
		if state.Version == tls.VersionTLS12 && strings.HasPrefix(tls.CipherSuiteName(state.CipherSuite), "TLS_RSA_WITH_") &&
			len(state.PeerCertificates) > 0 {
			key, strength := publicKeyStrength(state.PeerCertificates[0].PublicKey)
			return "RSA key transport / " + key, strength
		}
		return "Unavailable", 0
	default:
		return state.CurveID.String() + " (unsupported strength)", 0
	}
}

func cipherStrength(suite uint16) int {
	name := tls.CipherSuiteName(suite)
	switch {
	case strings.Contains(name, "_AES_128_"):
		return 128
	case strings.Contains(name, "_AES_256_"), strings.Contains(name, "_CHACHA20_POLY1305_"):
		return 256
	default:
		return 0
	}
}

func overallTLSStrength(state tls.ConnectionState) (int, string) {
	if state.Version != tls.VersionTLS12 && state.Version != tls.VersionTLS13 {
		return 0, "TLS version unavailable or unsupported"
	}
	strength := cipherStrength(state.CipherSuite)
	if strength == 0 {
		return 0, "Cipher strength unavailable or unsupported"
	}
	_, exchange := keyExchangeStrength(state)
	if exchange == 0 {
		return 0, "Key exchange strength unavailable or unsupported"
	}
	strength = min(strength, exchange)
	certificate, reason := verifiedCertificateStrength(state)
	if reason != "" {
		return 0, reason
	}
	return min(strength, certificate), ""
}

func verifiedCertificateStrength(state tls.ConnectionState) (int, string) {
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return 0, "Verified certificate chain unavailable"
	}
	_, leaf := publicKeyStrength(state.PeerCertificates[0].PublicKey)
	if leaf == 0 {
		return 0, "Leaf certificate key strength unavailable or unsupported"
	}
	strength := leaf
	for _, chain := range state.VerifiedChains {
		if len(chain) == 0 {
			return 0, "Verified certificate chain unavailable"
		}
		for i, cert := range chain {
			_, key := publicKeyStrength(cert.PublicKey)
			if key == 0 {
				return 0, "Certificate chain key strength unavailable or unsupported"
			}
			strength = min(strength, key)
			// A trust anchor's self-signature is not part of path validation.
			if i < len(chain)-1 {
				signature := signatureStrength(cert.SignatureAlgorithm)
				if signature == 0 {
					return 0, "Certificate chain signature strength unavailable or unsupported"
				}
				strength = min(strength, signature)
			}
		}
	}
	return strength, ""
}

func equivalentStrength(bits int) string {
	if bits == 0 {
		return "Unavailable"
	}
	return fmt.Sprintf("~%dbit", bits)
}

func (r *TestReport) TLS(state tls.ConnectionState) {
	if r == nil {
		return
	}
	now := time.Now()
	rows := []table.Row{
		{"TLS version", tls.VersionName(state.Version)},
	}
	cryptoRows := []table.Row{
		{"Cipher suite", tls.CipherSuiteName(state.CipherSuite), equivalentStrength(cipherStrength(state.CipherSuite))},
	}
	exchange, bits := keyExchangeStrength(state)
	cryptoRows = append(cryptoRows, table.Row{"Key exchange", exchange, equivalentStrength(bits)})
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		key, bits := publicKeyStrength(cert.PublicKey)
		names := append([]string(nil), cert.DNSNames...)
		for _, address := range cert.IPAddresses {
			names = append(names, address.String())
		}
		rows = append(rows,
			table.Row{"Subject", cert.Subject.String()},
			table.Row{"Issuer", cert.Issuer.String()},
			table.Row{"Subject alternative names", strings.Join(names, ", ")},
		)
		cryptoRows = append(cryptoRows,
			table.Row{"Certificate key", key, equivalentStrength(bits)},
			table.Row{"Certificate signature", cert.SignatureAlgorithm.String(), "-"},
		)
	} else {
		rows = append(rows, table.Row{"Certificate", "Unavailable"})
	}
	chain, _ := verifiedCertificateStrength(state)
	cryptoRows = append(cryptoRows, table.Row{"Verified certificate chain", "Weakest verified certificate key/signature", equivalentStrength(chain)})
	overall, reason := overallTLSStrength(state)
	cryptoRows = append(cryptoRows, table.Row{"TLS overall strength", "Weakest observable TLS component", equivalentStrength(overall)})
	if reason != "" {
		cryptoRows = append(cryptoRows, table.Row{"TLS estimate limitation", reason, "-"})
	}
	var certificates []*x509.Certificate
	addCertificate := func(cert *x509.Certificate) {
		for _, previous := range certificates {
			if cert == previous || (len(cert.Raw) > 0 && cert.Equal(previous)) {
				return
			}
		}
		certificates = append(certificates, cert)
	}
	for _, cert := range state.PeerCertificates {
		addCertificate(cert)
	}
	for _, chain := range state.VerifiedChains {
		for _, cert := range chain {
			addCertificate(cert)
		}
	}
	validity := make([]certificateValidity, len(certificates))
	for i, cert := range certificates {
		label := fmt.Sprintf("TLS certificate %d", i+1)
		if cert.Subject.CommonName != "" {
			label += " (CN=" + cert.Subject.CommonName + ")"
		}
		validity[i] = certificateValidity{label, cert.NotBefore, cert.NotAfter}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tlsDetails = rows
	r.tlsCrypto = cryptoRows
	r.tlsValidity = validity
	r.tlsStrength, r.tlsStrengthReason = overall, reason
	r.values["Transport security"] = tlsTransportSummary(state, now)
}

func (r *TestReport) tlsDetailsTable() reportTable {
	rows := r.tlsDetails
	if len(rows) == 0 {
		status := r.values["Transport security"]
		if status == "" {
			status = "TLS not established / unavailable"
		}
		rows = []table.Row{{"Status", status}}
	}
	return reportTable{
		header: table.Row{"Property", "Details"},
		rows:   rows, configs: []table.ColumnConfig{
			{Number: 2, WidthMax: 76},
		},
	}
}

func (r *TestReport) renderTLSDetails(format reportFormat) string {
	t := r.tlsDetailsTable()
	if format == reportPlain {
		t.header = nil
	}
	return reportNote(format, "Server TLS certificate / connection") + "\n" +
		t.render(format, r.color, r.values["AD domain"]) + "\n" +
		r.renderCrypto(format) + "\n" + r.renderValidity(format)
}
