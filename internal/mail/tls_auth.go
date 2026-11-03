package mail

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/smtp"
	"net/textproto"
	"slices"
	"strings"
	"time"
)

type CertificateInfo struct {
	Subject              string    `json:"subject"`
	Issuer               string    `json:"issuer"`
	SHA256               string    `json:"sha256"`
	NotBefore            time.Time `json:"not_before"`
	NotAfter             time.Time `json:"not_after"`
	PublicKeyAlgorithm   string    `json:"public_key_algorithm"`
	SignatureAlgorithm   string    `json:"signature_algorithm"`
	PublicKey            string    `json:"public_key"`
	ClassicalKeyStrength int       `json:"classical_key_strength_bits"`
}

type ServerVerificationInfo struct {
	RootMode                  RootMode      `json:"root_mode"`
	AnchorSHA256              string        `json:"anchor_sha256"`
	Trusted                   bool          `json:"trusted_issuer"`
	PolicyPassed              bool          `json:"policy_passed"`
	AllowConfigured           bool          `json:"ca_allow_configured"`
	DenyConfigured            bool          `json:"ca_deny_configured"`
	ExpiryGrace               time.Duration `json:"expiry_grace_nanoseconds"`
	IssuerExceptionConfigured bool          `json:"issuer_exception_configured"`
	ExpiryExceptionUsed       bool          `json:"expiry_exception_used"`
	IssuerExceptionUsed       bool          `json:"issuer_exception_used"`
}

type AuthenticationResult struct {
	Method                     AuthMode               `json:"method"`
	TLSEstablished             bool                   `json:"tls_established"`
	ClientCertificateRequested bool                   `json:"client_certificate_requested"`
	ClientCertificatePresented bool                   `json:"client_certificate_presented"`
	SMTPAuthConfirmed          bool                   `json:"smtp_auth_confirmed"`
	ClientCertificate          *CertificateInfo       `json:"client_certificate,omitempty"`
	ServerVerification         ServerVerificationInfo `json:"server_verification"`
}

func certificateInfo(cert *x509.Certificate) *CertificateInfo {
	hash := sha256.Sum256(cert.Raw)
	key, strength := publicKeyStrength(cert.PublicKey)
	return &CertificateInfo{Subject: cert.Subject.String(), Issuer: cert.Issuer.String(), SHA256: hex.EncodeToString(hash[:]),
		NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(), SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKey: key, ClassicalKeyStrength: strength}
}

func authenticationTLS(o options, log io.Writer) (*tls.Config, *AuthenticationResult, error) {
	method := o.auth
	if method == "" {
		method = AuthGSSAPI
	}
	evidence := &AuthenticationResult{Method: method}
	evidence.ServerVerification.RootMode = o.serverTrust.Mode
	if evidence.ServerVerification.RootMode == "" {
		evidence.ServerVerification.RootMode = RootsSystem
	}
	evidence.ServerVerification.ExpiryGrace = o.serverTrust.ExpiredServerCertificateGrace
	evidence.ServerVerification.IssuerExceptionConfigured = o.serverTrust.InsecureAllowUnverifiableIssuer
	evidence.ServerVerification.AllowConfigured = len(o.serverTrust.Allow) > 0
	evidence.ServerVerification.DenyConfigured = len(o.serverTrust.Deny) > 0
	roots, err := serverRoots(o.serverTrust)
	if err != nil {
		return nil, nil, err
	}
	config := &tls.Config{ServerName: o.relay, MinVersion: tls.VersionTLS12, RootCAs: roots}
	relaxed := o.serverTrust.ExpiredServerCertificateGrace > 0 || o.serverTrust.InsecureAllowUnverifiableIssuer
	if relaxed {
		detail := fmt.Sprintf("explicit insecure server TLS options: expiry grace=%s; unverifiable issuer=%t; hostname and non-exempt checks remain required",
			o.serverTrust.ExpiredServerCertificateGrace, o.serverTrust.InsecureAllowUnverifiableIssuer)
		if o.report != nil {
			o.report.Line("WARN", "Server TLS policy", detail)
		} else {
			fmt.Fprintln(log, "Warning:", detail)
		}
		// The paired callback below enforces every non-exempt check.
		config.InsecureSkipVerify = true
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		now := time.Now()
		var verification serverVerification
		var err error
		if relaxed {
			verification, err = verifyServerCertificate(state.PeerCertificates, roots, o.serverTrust, o.relay, now)
		} else {
			verification.chain, err = acceptableServerChain(state.VerifiedChains, o.serverTrust, now)
		}
		if err != nil {
			return err
		}
		if len(verification.chain) == 0 {
			return errors.New("server verification produced no certificate chain")
		}
		anchor := verification.chain[len(verification.chain)-1]
		evidence.ServerVerification.AnchorSHA256 = certificateInfo(anchor).SHA256
		evidence.ServerVerification.PolicyPassed = true
		evidence.ServerVerification.Trusted = !verification.issuerUsed
		evidence.ServerVerification.ExpiryExceptionUsed = verification.expiryUsed
		evidence.ServerVerification.IssuerExceptionUsed = verification.issuerUsed
		if verification.expiryUsed || verification.issuerUsed {
			detail := fmt.Sprintf("server verification relaxed: expired leaf=%t; untrusted issuer=%t; server SHA256=%s",
				verification.expiryUsed, verification.issuerUsed, certificateInfo(state.PeerCertificates[0]).SHA256)
			if o.report != nil {
				o.report.Line("WARN", "Server TLS verification exception", detail)
			} else {
				fmt.Fprintln(log, "Warning:", detail)
			}
		}
		return nil
	}
	if method != AuthGSSAPI {
		if err := validateClientCertificate(o.clientCertificate, time.Now()); err != nil {
			return nil, nil, err
		}
		evidence.ClientCertificate = certificateInfo(o.clientCertificate.Leaf)
		config.GetClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			evidence.ClientCertificateRequested = true
			if err := validateClientCertificate(o.clientCertificate, time.Now()); err != nil {
				return nil, err
			}
			if err := request.SupportsCertificate(o.clientCertificate); err != nil {
				return nil, fmt.Errorf("client certificate incompatible with relay request: %w", err)
			}
			evidence.ClientCertificatePresented = true
			return o.clientCertificate, nil
		}
	}
	return config, evidence, nil
}

func externalAuthentication(c *smtp.Client) error {
	ok, mechanisms := c.Extension("AUTH")
	if !ok || !slices.ContainsFunc(strings.Fields(mechanisms), func(s string) bool { return strings.EqualFold(s, "EXTERNAL") }) {
		return errors.New("relay does not advertise AUTH EXTERNAL after TLS")
	}
	command := func(value string) (int, string, error) {
		id, err := c.Text.Cmd("%s", value)
		if err != nil {
			return 0, "", err
		}
		c.Text.StartResponse(id)
		defer c.Text.EndResponse(id)
		return c.Text.ReadResponse(0)
	}
	code, message, err := command("AUTH EXTERNAL =")
	if err != nil {
		return err
	}
	if code == 334 {
		if message != "" {
			return errors.New("unexpected non-empty SMTP EXTERNAL challenge")
		}
		code, message, err = command("=")
		if err != nil {
			return err
		}
	}
	if code != 235 {
		return &textproto.Error{Code: code, Msg: message}
	}
	return nil
}

func reportAuthentication(o options, result AuthenticationResult) {
	o.report.authenticationResult(result)
	if o.authentication != nil {
		if result.ClientCertificate != nil {
			copyCertificate := *result.ClientCertificate
			result.ClientCertificate = &copyCertificate
		}
		o.authentication(result)
	}
}

func (r *TestReport) authenticationResult(result AuthenticationResult) {
	if r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		if result.ClientCertificate != nil {
			copyCertificate := *result.ClientCertificate
			result.ClientCertificate = &copyCertificate
		}
		r.authentication = result
		if result.Method != AuthGSSAPI {
			previous := r.values["Authentication"]
			r.values["Authentication method"] = string(result.Method)
			switch {
			case result.SMTPAuthConfirmed:
				r.values["Authentication"] = "OK (SMTP AUTH EXTERNAL confirmed)"
			case result.Method == AuthMTLS && result.ClientCertificatePresented:
				r.values["Authentication"] = "Certificate presented; no SMTP AUTH; relay authorization not independently confirmed"
			case result.ClientCertificatePresented:
				r.values["Authentication"] = "Certificate presented; SMTP AUTH not confirmed"
			default:
				r.values["Authentication"] = "Client certificate not presented; SMTP AUTH not confirmed"
			}
			if strings.HasPrefix(previous, "FAILED:") {
				r.values["Authentication"] = previous + "; " + r.values["Authentication"]
			}
		}
		policy := result.ServerVerification
		if result.TLSEstablished && (policy.ExpiryExceptionUsed || policy.IssuerExceptionUsed) {
			r.values["Transport security"] = fmt.Sprintf("WARNING: TLS established under explicit exceptions (expired leaf=%t; untrusted issuer=%t); not strict verification",
				policy.ExpiryExceptionUsed, policy.IssuerExceptionUsed)
		}
	}
}

func (r *TestReport) AuthenticationMethod(method AuthMode) {
	if r == nil {
		return
	}
	if method == "" {
		method = AuthGSSAPI
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authentication.Method = method
	r.values["Authentication method"] = strings.ToUpper(string(method))
	if method != AuthGSSAPI {
		r.values["Authentication method"] = string(method)
		for _, key := range []string{"User", "SPN", "Cred source"} {
			r.values[key] = "Not applicable (certificate authentication; no Kerberos)"
		}
	}
}
